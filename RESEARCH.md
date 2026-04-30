# Research Papers and Implementation Reference

This document catalogs the academic research and industry standards that informed the design and implementation of piie (Privacy Layer for Agentic AI Systems).

---

## 1. Regular Expression-Based PII Detection

**Foundation:** Pattern-based PII detection using regular expressions

**What Was Implemented:**
- Regex patterns for detecting common PII types in `detectors.py`:
  - Email addresses: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
  - Phone numbers: `\+?[\d\s-]{10,}`
  - IPv4 addresses: `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`
  - Social Security Numbers: `\b\d{3}-\d{2}-\d{4}\b`
  - Credit Card numbers: `\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`
- Confidence scoring for each match type (default 0.95 for regex matches)
- Recursive JSON traversal for structured data in `detect_in_json()`

**Not Implemented (Future Work):**
- Contextual NER using ML models (spaCy, transformers)
- Custom pattern plugins for organization-specific identifiers

---

## 2. Deterministic Pseudonymization via Hash-Based Tokenization

**Foundation:** SHA256-based deterministic token generation for consistent pseudonymization

**What Was Implemented:**
- `PseudonymizationEngine` class in `sanitizers.py`
- Token generation algorithm:
  ```python
  hash_input = f"{salt}:{value}:{entity_type}"
  hash_digest = SHA256(hash_input)
  token = f"{entity_type}_{hash_digest[:8].upper()}"
  ```
- Consistent mapping: same input always produces same token
- In-memory caching for performance
- Redis-backed distributed cache in `storage/token_cache.py` for production deployments

**Key Property:** Enables cross-request correlation while maintaining privacy

---

## 3. Risk Scoring for Privacy Violations

**Foundation:** Weighted risk scoring based on PII entity sensitivity

**What Was Implemented:**
- `calculate_risk_score()` method in `sanitizers.py`
- Risk weights by entity type:
  | Entity Type | Risk Weight |
  |-------------|-------------|
  | SSN | 1.0 |
  | Credit Card | 1.0 |
  | Email | 0.5 |
  | Phone | 0.5 |
  | Name | 0.4 |
  | IP Address | 0.3 |
- Normalized output (0.0 to 1.0, capped at 1.0)
- Use cases: audit flagging, automated review triggers, blocking thresholds

---

## 4. Policy-Driven Sanitization Actions

**Foundation:** Configurable policy engine for privacy enforcement

**What Was Implemented:**
- Four sanitization actions in `SanitizationAction` enum:
  - `ALLOW` - Pass through unchanged
  - `REDACT` - Replace with type-specific placeholder (e.g., `[EMAIL_REDACTED]`)
  - `PSEUDONYMIZE` - Replace with deterministic token
  - `BLOCK` - Reject request entirely
- YAML-based policy configuration (`config/policy.yaml`)
- Entity-type to action mapping
- Policy evaluation without mutation (`evaluate_policy` tool)

---

## 5. Middleware Architecture for Automatic Privacy Enforcement

**Foundation:** ASGI middleware pattern for transparent request/response processing

**What Was Implemented:**
- `PIIMiddleware` class extending Starlette's `BaseHTTPMiddleware`
- Automatic interception of all HTTP requests
- Configurable exclude paths (`/health`, `/docs`, `/openapi.json`)
- Response headers for observability:
  - `X-PII-Detected`
  - `X-PII-Count`
  - `X-Risk-Score`
  - `X-Process-Time`
- Audit event logging for compliance

---

## 6. Audit Logging for Compliance

**Foundation:** Immutable audit trail for GDPR/HIPAA compliance

**What Was Implemented:**
- In-memory audit store in `storage/audit_store.py`
- Event schema:
  ```python
  {
      "event_id": str,
      "timestamp": datetime,
      "tenant_id": str,
      "trace_id": str,
      "action": str,
      "entities_found": int,
      "metadata": dict
  }
  ```
- Postgres-backed persistent store (via Supabase) for production
- Search endpoint for audit retrieval

---

## 7. Model Context Protocol (MCP) Server

**Foundation:** Anthropic's Model Context Protocol for AI agent integration

**What Was Implemented:**
- MCP server in `mcp_server.py`
- Tools:
  - `sanitize_text` - Sanitize plain text
  - `sanitize_json` - Sanitize JSON payloads
  - `evaluate_policy` - Policy simulation without mutation
  - `batch_sanitize` - Bulk processing
  - `search_audit_events` - Compliance queries
  - `validate_policy` - Policy syntax validation
  - `create_policy` - Policy creation
  - `list_policies` - Policy enumeration
  - `simulate_policy` - Draft policy testing
- Resources:
  - `piisafe://schemas/entities` - Entity type reference
  - `piisafe://docs/policy-language` - Policy documentation
  - `piisafe://health/status` - Service health
- Prompts:
  - `privacy-review-request` - Privacy risk review generation
  - `draft-redaction-policy` - Policy draft from business rules
  - `compliance-audit-summary` - Compliance reporting

---

## 8. Multi-Tenant Architecture

**Foundation:** Tenant-scoped policies and audit isolation

**What Was Implemented:**
- `tenant_id` parameter on all MCP tools and API endpoints
- Namespace isolation for token cache (`pii-safe:tokens:{namespace}:...`)
- Tenant-filtered policy loading
- Tenant-filtered audit event queries

---

## Standards Compliance

### GDPR (General Data Protection Regulation)
- **Article 25 (Data Protection by Design):** PII detection before processing
- **Article 32 (Security of Processing):** Pseudonymization as appropriate measure
- **Article 33 (Breach Notification):** Audit trail for incident response

### HIPAA (Health Insurance Portability and Accountability Act)
- **Safe Harbor Method:** Redaction of 18 PHI identifiers
- **Audit Controls:** Event logging for access tracking

---

## Not Yet Implemented (Future Research Integration)

| Feature | Research Basis | Status |
|---------|----------------|--------|
| ML-based NER (spaCy, transformers) | Named Entity Recognition models | Backlog |
| Differential privacy | Statistical disclosure control | Not planned |
| Homomorphic encryption | Privacy-preserving computation | Not planned |
| Federated learning integration | Distributed model training | Not planned |
| Context-aware detection | Language model-based PII classification | Backlog |

---

## Related Files

- `detectors.py` - PII detection engine
- `sanitizers.py` - Transformation engine
- `middleware/pii_middleware.py` - Request processing layer
- `storage/token_cache.py` - Distributed tokenization
- `storage/audit_store.py` - Compliance logging
- `mcp_server.py` - AI agent integration
