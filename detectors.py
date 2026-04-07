"""
PII Detection Module

Detects personally identifiable information in text and structured data.
Supports emails, phone numbers, IP addresses, and custom patterns.
"""

import re
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum


class EntityType(Enum):
    """Types of PII entities that can be detected."""
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    IP_ADDRESS = "IP_ADDRESS"
    NAME = "NAME"
    SSN = "SSN"
    CREDIT_CARD = "CREDIT_CARD"
    CUSTOM = "CUSTOM"


@dataclass
class PIIMatch:
    """Represents a detected PII entity."""
    entity_type: EntityType
    value: str
    start_pos: int
    end_pos: int
    confidence: float


class PIIDetector:
    """
    Main detector class for finding PII in text.

    Uses regex patterns and can be extended with NER models.
    """

    # Regex patterns for common PII types
    PATTERNS = {
        EntityType.EMAIL: r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        EntityType.PHONE: r'\+?[\d\s-]{10,}',
        EntityType.IP_ADDRESS: r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        EntityType.SSN: r'\b\d{3}-\d{2}-\d{4}\b',
        EntityType.CREDIT_CARD: r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
    }

    def __init__(self, custom_patterns: Dict[str, str] = None):
        """
        Initialize the detector with optional custom patterns.

        Args:
            custom_patterns: Dictionary of {pattern_name: regex_string}
        """
        self.compiled_patterns = {}

        # Compile built-in patterns
        for entity_type, pattern in self.PATTERNS.items():
            self.compiled_patterns[entity_type] = re.compile(pattern)

        # Add custom patterns
        if custom_patterns:
            for name, pattern in custom_patterns.items():
                self.compiled_patterns[name] = re.compile(pattern)

    def detect(self, text: str) -> List[PIIMatch]:
        """
        Scan text for PII entities.

        Args:
            text: Input text to scan

        Returns:
            List of detected PIIMatch objects
        """
        matches = []

        for entity_type, regex in self.compiled_patterns.items():
            for match in regex.finditer(text):
                matches.append(PIIMatch(
                    entity_type=entity_type,
                    value=match.group(),
                    start_pos=match.start(),
                    end_pos=match.end(),
                    confidence=0.95  # High confidence for regex matches
                ))

        # Sort by position
        matches.sort(key=lambda m: m.start_pos)
        return matches

    def detect_in_json(self, data: Any, path: str = "") -> List[Dict]:
        """
        Recursively detect PII in JSON-like structures.

        Args:
            data: Dictionary or list to scan
            path: Current JSON path (for reporting)

        Returns:
            List of detections with their JSON paths
        """
        detections = []

        if isinstance(data, dict):
            for key, value in data.items():
                new_path = f"{path}.{key}" if path else key
                detections.extend(self.detect_in_json(value, new_path))
        elif isinstance(data, list):
            for i, item in enumerate(data):
                detections.extend(self.detect_in_json(item, f"{path}[{i}]"))
        elif isinstance(data, str):
            matches = self.detect(data)
            for match in matches:
                detections.append({
                    "path": path,
                    "entity_type": match.entity_type.value,
                    "value": match.value,
                    "position": f"{match.start_pos}-{match.end_pos}"
                })

        return detections
