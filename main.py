"""
PII-Safe: Privacy Middleware for Agentic AI Systems

Main entry point for the PII-Safe application.
Initializes and runs the FastAPI server with privacy middleware.
"""

from fastapi import FastAPI
from middleware.pii_middleware import PIIMiddleware
from config import load_config

app = FastAPI(title="PII-Safe", description="Privacy Layer for AI Systems")

# Load privacy configuration
config = load_config("config/policy.yaml")

# Initialize and attach PII middleware
middleware = PIIMiddleware(config)
app.add_middleware(middleware)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "pii-safe"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
