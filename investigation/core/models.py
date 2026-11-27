"""Core data models: Event, Finding, Severity, EvidenceType."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity: {value!r}") from None

    def __str__(self) -> str:
        return self.name.lower()


class EvidenceType(str, enum.Enum):
    """What an artifact proves."""

    EXECUTION = "execution"
    EXISTENCE = "existence"
    FILE_ACCESS = "file_access"
    USER_ACTIVITY = "user_activity"
    PERSISTENCE = "persistence"
    DEVICE = "device"
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    OTHER = "other"

    def __str__(self) -> str:
        return self.value


def json_safe(value: Any) -> Any:
    """Reduce a value to str|int|float|bool|None."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, enum.Enum):
        return json_safe(value.value)
    return str(value)


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    timestamp_desc: str
    artifact: str
    source_file: str
    message: str
    host: str | None = None
    user: str | None = None
    fields: Mapping[str, Any] = field(default_factory=dict)
    tags: tuple[str, ...] = ()
    evidence_type: EvidenceType = EvidenceType.OTHER

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("Event.timestamp must be timezone-aware")

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "timestamp_desc": self.timestamp_desc,
            "artifact": self.artifact,
            "source_file": self.source_file,
            "host": self.host,
            "user": self.user,
            "message": self.message,
            "evidence_type": str(EvidenceType(self.evidence_type)),
            "fields": {str(k): json_safe(v) for k, v in self.fields.items()},
            "tags": list(self.tags),
        }


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    description: str
    mitre: tuple[str, ...]
    events: list[Event]
    note: str | None = None
    tactics: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": str(self.severity),
            "description": self.description,
            "note": self.note,
            "mitre": list(self.mitre),
            "tactics": list(self.tactics),
            "events": [e.to_dict() for e in self.events],
        }
