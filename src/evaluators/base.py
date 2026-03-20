from __future__ import annotations

from abc import ABC, abstractmethod

from contracts.models import AppOutput, MetricResult
from dataset.schema import TestCase


class BaseEvaluator(ABC):
    """
    Abstract base class for all GenAI evaluation modules.

    Each evaluator is responsible for scoring one quality dimension
    of a GenAI system's output. Evaluators receive the system output
    and the original test case, then return a standardized MetricResult.

    Subclasses must implement:
        name  — a unique string identifier for the metric
        evaluate — the scoring logic that produces a MetricResult

    Example:
        class CorrectnessEvaluator(BaseEvaluator):
            name = "correctness"

            def evaluate(self, case, output):
                ...
                return MetricResult(name=self.name, score=..., passed=..., reason=...)
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Unique identifier for the metric this evaluator produces.

        Used in MetricResult.name and for filtering, reporting,
        and threshold comparisons.
        """

    @abstractmethod
    def evaluate(self, case: TestCase, output: AppOutput) -> MetricResult:
        """
        Score a single GenAI system output against a test case.

        Args:
            case:   The test case containing the query, expectations,
                    thresholds, and gold checks.
            output: The standardized output produced by the system
                    under test.

        Returns:
            MetricResult with the evaluator's name, numeric score,
            pass/fail status, and a human-readable reason.
        """
