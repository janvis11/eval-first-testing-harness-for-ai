"""
Policy API Routes

Endpoints for managing privacy policies.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import yaml

from config import load_config, validate_config, create_default_config

router = APIRouter(prefix="/policy", tags=["policy"])


class PolicyInput(BaseModel):
    """Input for creating/updating a policy."""
    name: str
    entity_types: List[str]
    action: str


class PolicyResponse(BaseModel):
    """Policy response."""
    name: str
    entity_types: List[str]
    action: str


class ConfigResponse(BaseModel):
    """Full configuration response."""
    policies: List[PolicyResponse]
    audit_logging: bool
    risk_scoring: bool


@router.get("", response_model=ConfigResponse)
@router.get("/", response_model=ConfigResponse)
async def get_policy():
    """
    Get current privacy policy configuration.

    Returns:
        Current configuration with all policies
    """
    config = load_config("config/policy.yaml")
    return ConfigResponse(
        policies=[
            PolicyResponse(
                name=p["name"],
                entity_types=p["entity_types"],
                action=p["action"]
            )
            for p in config.get("policies", [])
        ],
        audit_logging=config.get("audit_logging", True),
        risk_scoring=config.get("risk_scoring", True)
    )


@router.post("", response_model=ConfigResponse)
@router.post("/", response_model=ConfigResponse)
async def update_policy(config: ConfigResponse):
    """
    Update privacy policy configuration.

    Args:
        config: New configuration

    Returns:
        Updated configuration
    """
    config_dict = {
        "policies": [
            {
                "name": p.name,
                "entity_types": p.entity_types,
                "action": p.action
            }
            for p in config.policies
        ],
        "audit_logging": config.audit_logging,
        "risk_scoring": config.risk_scoring
    }

    try:
        validate_config(config_dict)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Save to file
    with open("config/policy.yaml", "w") as f:
        yaml.dump(config_dict, f, default_flow_style=False)

    return config


@router.post("/add", response_model=ConfigResponse)
async def add_policy(policy: PolicyInput):
    """
    Add a new policy to the configuration.

    Args:
        policy: Policy to add

    Returns:
        Updated configuration
    """
    config = load_config("config/policy.yaml")

    # Check for duplicate name
    for existing in config.get("policies", []):
        if existing["name"] == policy.name:
            raise HTTPException(
                status_code=400,
                detail=f"Policy with name '{policy.name}' already exists"
            )

    # Validate action
    valid_actions = {"allow", "redact", "pseudonymize", "block"}
    if policy.action.lower() not in valid_actions:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action: {policy.action}. Must be one of: {valid_actions}"
        )

    config["policies"].append({
        "name": policy.name,
        "entity_types": policy.entity_types,
        "action": policy.action.lower()
    })

    # Save updated config
    with open("config/policy.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False)

    return ConfigResponse(
        policies=[
            PolicyResponse(
                name=p["name"],
                entity_types=p["entity_types"],
                action=p["action"]
            )
            for p in config.get("policies", [])
        ],
        audit_logging=config.get("audit_logging", True),
        risk_scoring=config.get("risk_scoring", True)
    )


@router.delete("/{policy_name}", response_model=ConfigResponse)
async def delete_policy(policy_name: str):
    """
    Delete a policy by name.

    Args:
        policy_name: Name of policy to delete

    Returns:
        Updated configuration
    """
    config = load_config("config/policy.yaml")

    original_count = len(config.get("policies", []))
    config["policies"] = [
        p for p in config.get("policies", [])
        if p["name"] != policy_name
    ]

    if len(config["policies"]) == original_count:
        raise HTTPException(
            status_code=404,
            detail=f"Policy '{policy_name}' not found"
        )

    # Save updated config
    with open("config/policy.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False)

    return ConfigResponse(
        policies=[
            PolicyResponse(
                name=p["name"],
                entity_types=p["entity_types"],
                action=p["action"]
            )
            for p in config.get("policies", [])
        ],
        audit_logging=config.get("audit_logging", True),
        risk_scoring=config.get("risk_scoring", True)
    )


@router.get("/reset", response_model=ConfigResponse)
async def reset_policy():
    """
    Reset to default configuration.

    Returns:
        Default configuration
    """
    config = create_default_config()

    with open("config/policy.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False)

    return ConfigResponse(
        policies=[
            PolicyResponse(
                name=p["name"],
                entity_types=p["entity_types"],
                action=p["action"]
            )
            for p in config.get("policies", [])
        ],
        audit_logging=config.get("audit_logging", True),
        risk_scoring=config.get("risk_scoring", True)
    )
