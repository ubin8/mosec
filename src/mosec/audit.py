from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True, frozen=True)
class AuditEntry:
    action: str
    subject_type: str
    subject_id: str | None = None
    decision: str | None = None
    reason: str | None = None
    actor: str | None = None
    created_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "subject_type": self.subject_type,
            "subject_id": self.subject_id,
            "decision": self.decision,
            "reason": self.reason,
            "actor": self.actor,
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
        }

    def to_summary(self) -> str:
        subject = self.subject_type
        if self.subject_id:
            subject = f"{subject}:{self.subject_id}"
        parts = [self.action, subject]
        if self.decision is not None:
            parts.append(f"decision={self.decision}")
        if self.reason is not None:
            parts.append(f"reason={self.reason}")
        return " ".join(parts)
