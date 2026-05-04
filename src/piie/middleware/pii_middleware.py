"""
PII Middleware for FastAPI

Intercepts incoming requests, detects PII in payloads,
applies sanitization policies, and logs audit events.
"""

import hashlib
import json
import time
import logging
from typing import Dict, Any, Optional, Callable, List
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from ..detectors import PIIDetector, PIIMatch
from ..sanitizers import PIISanitizer, SanitizationAction, PseudonymizationEngine
from ..config import (
    load_config,
    get_pseudonymization_config,
    get_audit_config,
    get_detector_config,
    get_sanitizer_config,
    get_middleware_config,
    get_risk_scoring_config,
)
from ..storage.pii_safe_audit import get_pii_safe_audit_store

logger = logging.getLogger(__name__)


class PIIMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware that applies PII detection and sanitization
    to incoming requests and outgoing responses.
    """

    def __init__(
        self,
        app: ASGIApp,
        config: Optional[Dict[str, Any]] = None,
        config_path: str = "config/policy.yaml",
        exclude_paths: Optional[list] = None
    ):
        """
        Initialize the PII middleware.

        Args:
            app: FastAPI application
            config: Pre-loaded configuration (optional)
            config_path: Path to YAML config file
            exclude_paths: List of paths to exclude from PII processing
        """
        super().__init__(app)
        self.config = config or load_config(config_path)

        # Load all configuration
        pseudo_config = get_pseudonymization_config()
        detector_config = get_detector_config()
        sanitizer_config = get_sanitizer_config()
        middleware_config = get_middleware_config()
        risk_config = get_risk_scoring_config()

        # Initialize detector with configuration
        self.detector = PIIDetector(
            enable_luhn=detector_config.enable_luhn_validation,
            exclude_test_domains=detector_config.exclude_test_domains,
            test_domains=detector_config.test_domains,
            min_phone_digits=detector_config.min_phone_digits,
            max_phone_digits=detector_config.max_phone_digits
        )

        # Initialize sanitizer with configuration
        self.sanitizer = PIISanitizer(
            pseudonym_engine=PseudonymizationEngine(
                salt=pseudo_config.salt,
                token_length=sanitizer_config.pseudonym_token_length
            ),
            risk_block_threshold=risk_config.risk_score_threshold_block
        )

        # Use configured exclude paths
        self.exclude_paths = exclude_paths or middleware_config.exclude_paths
        self.audit_log = []
        self.middleware_config = middleware_config
        self.risk_config = risk_config

        # Initialize PII-safe audit store
        audit_config = get_audit_config()
        if audit_config.audit_log_pii_redaction:
            try:
                self.audit_store = get_pii_safe_audit_store()
            except Exception as e:
                logger.warning(f"Could not initialize audit store: {e}")
                self.audit_store = None
            else:
                self.audit_store = None

    def _is_excluded_path(self, path: str) -> bool:
        """Return True when a path should bypass PII middleware."""
        for excluded in self.exclude_paths:
            if excluded == "/":
                if path == "/":
                    return True
                continue
            if path == excluded or path.startswith(f"{excluded.rstrip('/')}/"):
                return True
        return False

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process the request through PII detection and sanitization.

        Args:
            request: Incoming FastAPI request
            call_next: Next middleware/handler in chain

        Returns:
            Processed Response
        """
        # Skip excluded paths
        if self._is_excluded_path(request.url.path):
            return await call_next(request)

        # Track timing
        start_time = time.time()

        # Try to parse request body
        body = await self._get_request_body(request)

        # Detect PII in request body
        pii_matches = []
        if body:
            body_str = json.dumps(body) if isinstance(body, dict) else str(body)
            pii_matches = self.detector.detect(body_str)

        # Apply policies if PII found
        if pii_matches:
            policy_result = self._apply_policies(body_str, pii_matches)

            if policy_result.get("blocked"):
                # Log blocked request
                self._log_audit_event(
                    path=request.url.path,
                    method=request.method,
                    action="blocked",
                    entities_found=len(pii_matches),
                    reason=policy_result.get("reason", "Policy violation")
                )

                return Response(
                    content=json.dumps({
                        "error": "Request contains blocked PII",
                        "reason": policy_result.get("reason", "Policy violation")
                    }),
                    status_code=403,
                    media_type="application/json"
                )

            # Replace request body with sanitized version
            if policy_result.get("sanitized_body"):
                request._body = policy_result["sanitized_body"].encode()

            # Log the sanitization
            self._log_audit_event(
                path=request.url.path,
                method=request.method,
                action="sanitized",
                entities_found=len(pii_matches),
                transformations=policy_result.get("transformations", [])
            )

        # Process the request
        response = await call_next(request)

        # Calculate risk score
        risk_score = self.sanitizer.calculate_risk_score(pii_matches)

        # Add PII info to response headers
        response.headers["X-PII-Detected"] = str(len(pii_matches) > 0)
        response.headers["X-PII-Count"] = str(len(pii_matches))
        response.headers["X-Risk-Score"] = str(round(risk_score, 2))

        # Log processing time
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(round(process_time, 4))

        return response

    async def _get_request_body(self, request: Request) -> Optional[Any]:
        """Extract and parse request body."""
        try:
            body = await request.body()
            if not body:
                return None

            content_type = request.headers.get("content-type", "")
            if "application/json" in content_type:
                return json.loads(body.decode())
            return body.decode()
        except Exception as e:
            logger.warning(f"Failed to parse request body: {e}")
            return None

    def _apply_policies(self, text: str, matches: list) -> Dict[str, Any]:
        """
        Apply configured policies to detected PII.

        Args:
            text: Original text
            matches: List of detected PII matches

        Returns:
            Dictionary with sanitization results
        """
        result = {
            "blocked": False,
            "reason": None,
            "sanitized_body": text,
            "transformations": []
        }

        # Group matches by entity type for policy matching
        entities_by_type = {}
        for match in matches:
            entity_type = match.entity_type.value
            if entity_type not in entities_by_type:
                entities_by_type[entity_type] = []
            entities_by_type[entity_type].append(match)

        replacements = []

        # Apply each policy
        for policy in self.config.get("policies", []):
            policy_entities = [e.upper() for e in policy.get("entity_types", [])]
            action = policy.get("action", "redact").lower()

            # Find matching entities
            matching_matches = []
            for entity_type, type_matches in entities_by_type.items():
                if entity_type in policy_entities or "ALL" in policy_entities:
                    matching_matches.extend(type_matches)

            if not matching_matches:
                continue

            # Handle block action
            if action == "block":
                result["blocked"] = True
                result["reason"] = f"Blocked by policy: {policy.get('name', 'unnamed')}"
                return result

            for match in matching_matches:
                action_enum = SanitizationAction(action)

                if action_enum == SanitizationAction.REDACT:
                    replacement = self.sanitizer.redaction_templates.get(
                        match.entity_type, "[REDACTED]"
                    )
                elif action_enum == SanitizationAction.PSEUDONYMIZE:
                    if self.sanitizer.pseudonym_engine is None:
                        raise ValueError("Pseudonymization policy requires a configured salt")
                    replacement = self.sanitizer.pseudonym_engine.generate_token(
                        match.value,
                        match.entity_type,
                    )
                elif action_enum == SanitizationAction.ALLOW:
                    replacement = match.value
                else:
                    replacement = "[REDACTED]"

                replacements.append((match, replacement))

                # SECURITY: Never log original PII values.
                original_hash = hashlib.sha256(match.value.encode()).hexdigest()[:8]
                result["transformations"].append({
                    "original": f"{match.entity_type.value}_{original_hash}",
                    "original_hash": f"{match.entity_type.value}_{original_hash}",
                    "sanitized": replacement,
                    "entity_type": match.entity_type.value,
                    "action": action,
                    "policy": policy.get("name"),
                    "position": f"{match.start_pos}-{match.end_pos}"
                })

        sanitized_body = text
        seen_ranges = set()
        for match, replacement in sorted(
            replacements,
            key=lambda item: item[0].start_pos,
            reverse=True,
        ):
            match_range = (match.start_pos, match.end_pos)
            if match_range in seen_ranges:
                continue
            seen_ranges.add(match_range)
            sanitized_body = (
                sanitized_body[:match.start_pos]
                + replacement
                + sanitized_body[match.end_pos:]
            )

        result["sanitized_body"] = sanitized_body

        return result

    def _log_audit_event(self, **kwargs):
        """
        Log an audit event for compliance tracking.

        Uses PII-safe audit store to prevent sensitive data leakage.
        """
        event = {
            "timestamp": time.time(),
            **kwargs
        }
        self.audit_log.append(event)

        if self.config.get("audit_logging", True):
            # Log to console (already sanitized by _apply_policies)
            logger.info(f"PII Audit Event: {json.dumps(kwargs, default=str)}")

            # Also store in database if audit store is available
            if self.audit_store:
                try:
                    entities_found = kwargs.get("entities_found", [])
                    if not isinstance(entities_found, list):
                        entities_found = []

                    # Extract tenant_id from kwargs if available
                    tenant_id = kwargs.get("tenant_id", "unknown")
                    trace_id = kwargs.get("trace_id", hashlib.sha256(
                        f"{time.time()}:{kwargs.get('path', '')}".encode()
                    ).hexdigest()[:16])

                    self.audit_store.record_event(
                        tenant_id=tenant_id,
                        trace_id=trace_id,
                        action=kwargs.get("action", "unknown"),
                        entities_found=entities_found,
                        risk_score=kwargs.get("risk_score"),
                        policy_id=kwargs.get("policy_id"),
                        request_path=kwargs.get("path"),
                        request_method=kwargs.get("method"),
                        transformations=kwargs.get("transformations"),
                        metadata=kwargs.get("metadata")
                    )
                except Exception as e:
                    logger.error(f"Failed to store audit event: {e}")

    def get_audit_log(self) -> list:
        """Retrieve the audit log."""
        return self.audit_log
