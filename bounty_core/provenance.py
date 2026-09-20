"""Small, shared provenance tags for AI-reviewed durable records."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

AI_REVIEWED_BY_FIELD = "ai_reviewed_by"


def merge_ai_reviewers(
    existing: object = (),
    *,
    agent_id: object | None = None,
    model_id: object | None = None,
) -> list[dict[str, str]]:
    """Return deduplicated reviewer tags, preserving existing valid entries.

    A reviewer tag is intentionally compact and contains only the durable agent
    and model identifiers.  Both must be present; an unknown model must not be
    guessed or represented as a fake value.
    """
    reviewers: list[dict[str, str]] = []
    raw_values: Iterable[object]
    if isinstance(existing, Mapping):
        raw_values = (existing,)
    elif isinstance(existing, Iterable) and not isinstance(existing, (str, bytes)):
        raw_values = existing
    else:
        raw_values = ()

    for value in raw_values:
        normalized = _normalize_reviewer(value)
        if normalized is not None and normalized not in reviewers:
            reviewers.append(normalized)

    candidate = _normalize_reviewer({"agent_id": agent_id, "model_id": model_id})
    if candidate is not None and candidate not in reviewers:
        reviewers.append(candidate)
    return reviewers


def reviewer_labels(value: object = ()) -> list[str]:
    """Render valid reviewer tags for compact human-facing artifact headers."""
    return [f"{item['agent_id']}@{item['model_id']}" for item in merge_ai_reviewers(value)]


def _normalize_reviewer(value: object) -> dict[str, str] | None:
    if not isinstance(value, Mapping):
        return None
    agent_id = str(value.get("agent_id") or "").strip()
    model_id = str(value.get("model_id") or "").strip()
    if not agent_id or not model_id:
        return None
    return {"agent_id": agent_id, "model_id": model_id}
