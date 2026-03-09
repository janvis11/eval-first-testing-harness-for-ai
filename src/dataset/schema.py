from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class Expectations(BaseModel):
    """
    Behavioral rules the GenAI system is expected to follow for a test case.
    """

    must_refuse: bool = False
    must_abstain: bool = False
    require_citations: bool = False
    must_call_tool: Optional[str] = None

    @field_validator("must_call_tool")
    @classmethod
    def validate_tool_name(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value

        cleaned = value.strip()
        if not cleaned:
            raise ValueError("must_call_tool cannot be empty if provided")

        return cleaned


class Thresholds(BaseModel):
    """
    Numeric limits used to determine whether a test case passes or fails.
    """

    grounding_min: float = 0.0
    relevance_min: float = 0.0
    hallucination_risk_max: float = 1.0

    @field_validator("grounding_min", "relevance_min", "hallucination_risk_max")
    @classmethod
    def validate_score_range(cls, value: float) -> float:
        if not 0.0 <= value <= 1.0:
            raise ValueError("threshold values must be between 0.0 and 1.0")
        return value


class GoldChecks(BaseModel):
    """
    Content-level checks used to validate generated answers.
    """

    must_contain: List[str] = Field(default_factory=list)
    must_contain_any: List[str] = Field(default_factory=list)
    must_not_contain: List[str] = Field(default_factory=list)

    @field_validator("must_contain", "must_contain_any", "must_not_contain")
    @classmethod
    def validate_phrases(cls, values: List[str]) -> List[str]:
        cleaned_values = []

        for value in values:
            cleaned = value.strip()
            if not cleaned:
                raise ValueError("gold check phrases cannot be empty")
            cleaned_values.append(cleaned)

        return cleaned_values


class TestCase(BaseModel):
    """
    A single GenAI evaluation test case.
    """

    id: str
    query: str
    tags: List[str] = Field(default_factory=list)
    expectations: Expectations = Field(default_factory=Expectations)
    thresholds: Thresholds = Field(default_factory=Thresholds)
    gold: GoldChecks = Field(default_factory=GoldChecks)
    metadata: Dict[str, str] = Field(default_factory=dict)

    @field_validator("id", "query")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("field cannot be empty")
        return cleaned

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, values: List[str]) -> List[str]:
        cleaned_tags = []

        for value in values:
            cleaned = value.strip()
            if not cleaned:
                raise ValueError("tags cannot contain empty values")
            cleaned_tags.append(cleaned)

        return cleaned_tags


class TestSuite(BaseModel):
    """
    A collection of GenAI evaluation test cases loaded from a dataset file.
    """

    suite_name: str
    cases: List[TestCase]

    @field_validator("suite_name")
    @classmethod
    def validate_suite_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("suite_name cannot be empty")
        return cleaned