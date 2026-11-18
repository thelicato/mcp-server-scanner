from __future__ import annotations

import base64
import hashlib
import hmac
from enum import StrEnum

from mcp_test_server.weakness import WeaknessSet


class PkceWeakness(StrEnum):
    NOT_REQUIRED = "not_required"
    VERIFIER_UNCHECKED = "verifier_unchecked"
    PLAIN_ACCEPTED = "plain_accepted"


class PkcePolicy:
    def __init__(self, weaknesses: WeaknessSet[PkceWeakness]) -> None:
        self._weaknesses = weaknesses

    def challenge_error(self, challenge: str | None, method: str | None) -> str | None:
        if not challenge:
            return None if self._weaknesses.active(PkceWeakness.NOT_REQUIRED) else "invalid_request"
        if method == "S256" or (method == "plain" and self._weaknesses.active(PkceWeakness.PLAIN_ACCEPTED)):
            return None
        return "invalid_request"

    def verifier_matches(self, challenge: str | None, method: str | None, verifier: str | None) -> bool:
        if challenge is None or self._weaknesses.active(PkceWeakness.VERIFIER_UNCHECKED):
            return True
        if verifier is None:
            return False
        if method == "plain":
            return hmac.compare_digest(verifier, challenge)
        digest = hashlib.sha256(verifier.encode()).digest()
        return hmac.compare_digest(base64.urlsafe_b64encode(digest).rstrip(b"=").decode(), challenge)
