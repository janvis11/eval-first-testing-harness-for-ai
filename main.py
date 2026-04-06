"""
PII-Safe: Privacy Middleware for Agentic AI Systems

Main entry point for the PII-Safe application.
Initializes and runs the FastAPI server with privacy middleware.
"""

from fastapi import FastAPI
from middleware.pii_middleware import PIIMiddleware
from config import load_config

# Import routers
from routes.sanitize import router as sanitize_router
from routes.batch import router as batch_router
from routes.policy import router as policy_router
from routes.audit import router as audit_router

app = FastAPI(
    title="PII-Safe",
    description="Privacy Layer for Agentic AI Systems - Detects, manages, and sanitizes PII",
    version="1.0.0",
    contact={
        "name": "Janvi Singh",
        "url": "https://github.com/janvis11"
    }
)

# Load privacy configuration
config = load_config("config/policy.yaml")

# Initialize and attach PII middleware
middleware = PIIMiddleware(app, config)
app.add_middleware(middleware)

# Include routers
app.include_router(sanitize_router)
app.include_router(batch_router)
app.include_router(policy_router)
app.include_router(audit_router)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "pii-safe",
        "version": "1.0.0"
    }


@app.get("/")
async def root():
    """Root endpoint with service information."""
    return {
        "service": "PII-Safe",
        "description": "Privacy Layer for Agentic AI Systems",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": {
            "sanitize": "/sanitize",
            "batch": "/batch",
            "policy": "/policy",
            "audit": "/audit",
            "health": "/health"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
