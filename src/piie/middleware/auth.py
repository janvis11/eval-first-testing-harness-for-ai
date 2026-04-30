"""
Authentication and Authorization Middleware for PII-Safe

Provides API key authentication, tenant scoping, and RBAC.
Uses persistent database storage for tenants and API keys.
"""

import time
import hashlib
import secrets
from typing import Dict, Any, Optional, Callable, List
from functools import wraps
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from starlette.responses import JSONResponse

from ..storage.auth_store import get_auth_store, AuthStore


class APIKeyManager:
    """Manages API keys for service-to-service authentication using persistent storage."""

    def __init__(self, store: Optional[AuthStore] = None):
        self._store = store

    def _get_store(self) -> AuthStore:
        """Get or initialize the auth store."""
        if self._store is None:
            self._store = get_auth_store()
        return self._store

    def create_key(
        self,
        tenant_id: str,
        name: str,
        scopes: List[str],
        expires_at: Optional[float] = None
    ) -> str:
        """Create a new API key."""
        return self._get_store().create_key(tenant_id, name, scopes, expires_at)

    def validate_key(self, key: str) -> Optional[Dict[str, Any]]:
        """Validate an API key and return metadata if valid."""
        return self._get_store().validate_key(key)

    def revoke_key(self, key: str) -> bool:
        """Revoke an API key."""
        return self._get_store().revoke_key(key)

    def get_keys_for_tenant(self, tenant_id: str) -> List[Dict[str, Any]]:
        """Get all API keys for a tenant."""
        return self._get_store().get_keys_for_tenant(tenant_id)


class TenantManager:
    """Manages tenant metadata and isolation using persistent storage."""

    def __init__(self, store: Optional[AuthStore] = None):
        self._store = store

    def _get_store(self) -> AuthStore:
        """Get or initialize the auth store."""
        if self._store is None:
            self._store = get_auth_store()
        return self._store

    def create_tenant(
        self,
        tenant_id: str,
        name: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create a new tenant."""
        tenant = self._get_store().create_tenant(tenant_id, name, metadata)
        return {
            "tenant_id": tenant.tenant_id,
            "name": tenant.name,
            "metadata": tenant.metadata_json or {},
            "created_at": tenant.created_at.timestamp() if tenant.created_at else time.time(),
            "active": tenant.active
        }

    def get_tenant(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Get tenant by ID."""
        tenant = self._get_store().get_tenant(tenant_id)
        if not tenant:
            return None
        return {
            "tenant_id": tenant.tenant_id,
            "name": tenant.name,
            "metadata": tenant.metadata_json or {},
            "created_at": tenant.created_at.timestamp() if tenant.created_at else time.time(),
            "active": tenant.active
        }

    def list_tenants(self) -> List[Dict[str, Any]]:
        """List all tenants."""
        tenants = self._get_store().list_tenants()
        return [
            {
                "tenant_id": t.tenant_id,
                "name": t.name,
                "metadata": t.metadata_json or {},
                "created_at": t.created_at.timestamp() if t.created_at else time.time(),
                "active": t.active
            }
            for t in tenants
        ]


# Global instances - lazily initialized with database-backed store
api_key_manager = APIKeyManager()
tenant_manager = TenantManager()


def require_auth(func: Callable) -> Callable:
    """Decorator to require authentication on an endpoint."""
    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        api_key = request.headers.get("X-API-Key")

        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing API key. Provide X-API-Key header."
            )

        key_data = api_key_manager.validate_key(api_key)

        if not key_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired API key"
            )

        tenant = tenant_manager.get_tenant(key_data["tenant_id"])

        if not tenant or not tenant.get("active", True):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tenant is not active"
            )

        request.state.tenant_id = key_data["tenant_id"]
        request.state.api_key_data = key_data
        request.state.scopes = key_data.get("scopes", [])

        return await func(request, *args, **kwargs)

    return wrapper


def require_scope(required_scope: str) -> Callable:
    """Decorator to require a specific scope on an endpoint."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            scopes = getattr(request.state, "scopes", [])

            if "admin" in scopes:
                return await func(request, *args, **kwargs)

            if required_scope not in scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required scope: {required_scope}"
                )

            return await func(request, *args, **kwargs)

        return wrapper
    return decorator


class AuthMiddleware(BaseHTTPMiddleware):
    """Middleware that handles authentication and tenant scoping."""

    def __init__(
        self,
        app: ASGIApp,
        exclude_paths: Optional[List[str]] = None
    ):
        super().__init__(app)
        self.exclude_paths = exclude_paths or [
            "/health",
            "/docs",
            "/openapi.json",
            "/"
        ]

    async def dispatch(self, request: Request, call_next: Callable) -> Any:
        if any(request.url.path.startswith(p) for p in self.exclude_paths):
            request.state.tenant_id = None
            request.state.api_key_data = None
            request.state.scopes = []
            return await call_next(request)

        api_key = request.headers.get("X-API-Key")

        if not api_key:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "error": "Missing API key",
                    "detail": "Provide X-API-Key header for authentication"
                }
            )

        key_data = api_key_manager.validate_key(api_key)

        if not key_data:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "error": "Invalid API key",
                    "detail": "The provided API key is invalid or expired"
                }
            )

        tenant = tenant_manager.get_tenant(key_data["tenant_id"])

        if not tenant or not tenant.get("active", True):
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "error": "Tenant inactive",
                    "detail": "The tenant associated with this API key is not active"
                }
            )

        request.state.tenant_id = key_data["tenant_id"]
        request.state.api_key_data = key_data
        request.state.scopes = key_data.get("scopes", [])
        request.state.tenant = tenant

        response = await call_next(request)
        response.headers["X-Tenant-ID"] = key_data["tenant_id"]

        return response


def init_default_auth():
    """Initialize default tenant and API key for development/testing."""
    tenant_manager.create_tenant(
        tenant_id="default",
        name="Default Tenant",
        metadata={"environment": "development"}
    )

    default_key = api_key_manager.create_key(
        tenant_id="default",
        name="Default Development Key",
        scopes=["admin"],
        expires_at=None
    )

    return default_key


__all__ = [
    "AuthMiddleware",
    "APIKeyManager",
    "TenantManager",
    "api_key_manager",
    "tenant_manager",
    "require_auth",
    "require_scope",
    "init_default_auth"
]
