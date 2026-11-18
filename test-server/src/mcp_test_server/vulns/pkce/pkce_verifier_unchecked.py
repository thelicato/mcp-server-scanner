from __future__ import annotations

from mcp_test_server.oauth.pkce_policy import PkceWeakness
from mcp_test_server.vulns.pkce.pkce_vulnerability import PkceVulnerability


class PkceVerifierUnchecked(PkceVulnerability):
    name = "pkce_verifier_unchecked"
    summary = "/token redeems a code without checking the code_verifier against its code_challenge"
    weakness = PkceWeakness.VERIFIER_UNCHECKED
