from __future__ import annotations

from mcp_test_server.oauth.pkce_policy import PkceWeakness
from mcp_test_server.vulns.pkce.pkce_vulnerability import PkceVulnerability


class PkceNotRequired(PkceVulnerability):
    name = "pkce_not_required"
    summary = "/authorize issues a code without a code_challenge and /token redeems it without a code_verifier"
    weakness = PkceWeakness.NOT_REQUIRED
