from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CallContext:
    headers: Mapping[str, str]
    session_id: str | None = None
    session_owner: str | None = None
    notifications: list[dict[str, Any]] = field(default_factory=list, compare=False)

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    def notify(self, method: str) -> None:
        self.notifications.append({"jsonrpc": "2.0", "method": method})
