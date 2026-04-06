"""
Configuration loader for PII-Safe.

Loads and validates privacy policies from YAML configuration files.
"""

import yaml
from pathlib import Path
from typing import Dict, List, Any


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load privacy policy configuration from YAML file.

    Args:
        config_path: Path to the YAML configuration file

    Returns:
        Dictionary containing policy rules and settings

    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If config format is invalid
    """
    path = Path(config_path)

    if not path.exists():
        return create_default_config()

    with open(path, 'r') as f:
        config = yaml.safe_load(f)

    validate_config(config)
    return config


def create_default_config() -> Dict[str, Any]:
    """Create a default configuration with safe defaults."""
    return {
        "policies": [
            {
                "name": "redact_emails",
                "entity_types": ["EMAIL"],
                "action": "redact"
            },
            {
                "name": "redact_phones",
                "entity_types": ["PHONE"],
                "action": "redact"
            },
            {
                "name": "redact_ips",
                "entity_types": ["IP_ADDRESS"],
                "action": "redact"
            }
        ],
        "audit_logging": True,
        "risk_scoring": True
    }


def validate_config(config: Dict[str, Any]) -> None:
    """Validate the configuration structure."""
    if "policies" not in config:
        raise ValueError("Configuration must contain 'policies' key")

    valid_actions = {"allow", "redact", "pseudonymize", "block"}

    for policy in config["policies"]:
        if "name" not in policy:
            raise ValueError("Each policy must have a 'name'")
        if "entity_types" not in policy:
            raise ValueError("Each policy must have 'entity_types'")
        if "action" not in policy:
            raise ValueError("Each policy must have 'action'")
        if policy["action"].lower() not in valid_actions:
            raise ValueError(f"Invalid action: {policy['action']}")
