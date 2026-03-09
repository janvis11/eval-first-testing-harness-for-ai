from __future__ import annotations

from pathlib import Path
from typing import Union

import yaml
from pydantic import ValidationError

from dataset.schema import TestSuite


class DatasetLoadError(Exception):
    """Raised when a dataset file cannot be loaded or validated."""


def load_suite(path: Union[str, Path]) -> TestSuite:
    """
    Load a YAML evaluation dataset and validate it against the TestSuite schema.

    Args:
        path: Path to the dataset YAML file.

    Returns:
        A validated TestSuite object.

    Raises:
        DatasetLoadError: If the file is missing, unreadable, invalid YAML,
        empty, malformed, or fails schema validation.
    """
    dataset_path = Path(path)

    if not dataset_path.exists():
        raise DatasetLoadError(f"Dataset file not found: {dataset_path}")

    if not dataset_path.is_file():
        raise DatasetLoadError(f"Dataset path is not a file: {dataset_path}")

    try:
        raw_text = dataset_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DatasetLoadError(f"Failed to read dataset file: {dataset_path}") from exc

    if not raw_text.strip():
        raise DatasetLoadError(f"Dataset file is empty: {dataset_path}")

    try:
        raw_data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise DatasetLoadError(f"Invalid YAML in dataset file: {dataset_path}") from exc

    if raw_data is None:
        raise DatasetLoadError(f"Dataset file produced no data: {dataset_path}")

    if not isinstance(raw_data, dict):
        raise DatasetLoadError(
            f"Dataset root must be a mapping/object, got {type(raw_data).__name__}"
        )

    try:
        suite = TestSuite.model_validate(raw_data)
    except ValidationError as exc:
        raise DatasetLoadError(
            f"Dataset schema validation failed for file: {dataset_path}\n{exc}"
        ) from exc

    if not suite.cases:
        raise DatasetLoadError(f"Dataset must contain at least one test case: {dataset_path}")

    case_ids = [case.id for case in suite.cases]
    duplicate_ids = {case_id for case_id in case_ids if case_ids.count(case_id) > 1}
    if duplicate_ids:
        duplicates = ", ".join(sorted(duplicate_ids))
        raise DatasetLoadError(f"Duplicate test case ids found: {duplicates}")

    return suite