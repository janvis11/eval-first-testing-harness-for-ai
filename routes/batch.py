"""
Batch API Routes

Endpoints for processing multiple items at once.
"""

import json
from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import io

from detectors import PIIDetector
from sanitizers import PIISanitizer, SanitizationAction, PseudonymizationEngine

router = APIRouter(prefix="/batch", tags=["batch"])


class BatchItem(BaseModel):
    """Single item in a batch request."""
    content: Any
    id: Optional[str] = None


class BatchRequest(BaseModel):
    """Batch processing request."""
    items: List[BatchItem]
    action: Optional[str] = "redact"


class BatchResult(BaseModel):
    """Result for a single batch item."""
    id: Optional[str]
    original: Any
    sanitized: Any
    entities_found: int
    risk_score: float
    error: Optional[str] = None


class BatchResponse(BaseModel):
    """Batch processing response."""
    total: int
    processed: int
    errors: int
    results: List[BatchResult]


@router.post("", response_model=BatchResponse)
@router.post("/", response_model=BatchResponse)
async def batch_sanitize(request: BatchRequest):
    """
    Process multiple items in a single request.

    Args:
        request: BatchRequest with list of items

    Returns:
        BatchResponse with results for each item
    """
    detector = PIIDetector()
    sanitizer = PIISanitizer(PseudonymizationEngine())

    results = []
    errors = 0

    try:
        action = SanitizationAction(request.action or "redact")
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action: {request.action}"
        )

    for item in request.items:
        try:
            content_str = str(item.content) if not isinstance(item.content, str) else item.content

            matches = detector.detect(content_str)
            sanitized = sanitizer.sanitize(content_str, matches, action)

            results.append(BatchResult(
                id=item.id,
                original=item.content,
                sanitized=sanitized.sanitized,
                entities_found=len(matches),
                risk_score=sanitizer.calculate_risk_score(matches)
            ))
        except Exception as e:
            errors += 1
            results.append(BatchResult(
                id=item.id,
                original=item.content,
                sanitized=None,
                entities_found=0,
                risk_score=0,
                error=str(e)
            ))

    return BatchResponse(
        total=len(request.items),
        processed=len(results) - errors,
        errors=errors,
        results=results
    )


@router.post("/file")
async def batch_sanitize_file(
    file: UploadFile = File(...),
    action: Optional[str] = "redact"
):
    """
    Process a file containing multiple lines (JSONL format).

    Args:
        file: UploadFile with JSONL content
        action: Action to apply

    Returns:
        Processed results
    """
    detector = PIIDetector()
    sanitizer = PIISanitizer(PseudonymizationEngine())

    try:
        action = SanitizationAction(action or "redact")
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action: {action}"
        )

    contents = await file.read()
    lines = contents.decode().strip().split("\n")

    results = []
    for i, line in enumerate(lines):
        if not line.strip():
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            data = {"raw": line}

        content_str = json.dumps(data) if isinstance(data, dict) else str(data)
        matches = detector.detect(content_str)
        sanitized = sanitizer.sanitize(content_str, matches, action)

        results.append({
            "line": i + 1,
            "original": data,
            "sanitized": sanitized.sanitized,
            "entities_found": len(matches),
            "risk_score": sanitizer.calculate_risk_score(matches)
        })

    return {
        "filename": file.filename,
        "total_lines": len(results),
        "results": results
    }
