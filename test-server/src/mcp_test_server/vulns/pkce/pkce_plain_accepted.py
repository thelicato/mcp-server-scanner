from __future__ import annotations

from mcp_test_server.oauth.pkce_policy import PkceWeakness
from mcp_test_server.vulns.pkce.pkce_vulnerability import PkceVulnerability


class PkcePlainAccepted(PkceVulnerability):
    name = "pkce_plain_accepted"
    summary = "/authorize accepts code_challenge_method=plain although the metadata advertises only S256"
    weakness = PkceWeakness.PLAIN_ACCEPTED
