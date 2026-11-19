package com.mcpscanner.checks.catalog.tokenaudience;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;

final class TokenAudienceDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "token-audience",
            "MCP token audience validation",
            "While the scanning user's OAuth session holds a refresh token, refreshes it once with an RFC 8707 "
                    + "resource parameter naming an unrelated resource, then tries the new access token on tools/list "
                    + "beside the user's own token and two refused controls (no token and a malformed one). It "
                    + "reports when the MCP server accepts the token. A JWT whose aud names the unrelated resource "
                    + "proves the token was issued for it; an opaque token only suggests it. The check refreshes the "
                    + "live session again straight away so it keeps a token for this server, keeps any rotated "
                    + "refresh token, revokes the probe's access token through RFC 7009 when offered, and sends the "
                    + "refresh token only to a token endpoint whose metadata names the session's own issuer.",
            CheckKind.HOST,
            AuditIssueSeverity.HIGH,
            AuditIssueConfidence.CERTAIN,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#token-audience-binding-and-validation",
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices#token-passthrough",
                    "https://datatracker.ietf.org/doc/html/rfc8707"),
            "The MCP authorization specification requires an MCP server to accept only access tokens issued for it, "
                    + "checking the token's audience, and requires clients to name the server with the RFC 8707 "
                    + "resource parameter. A server that accepts tokens issued for other resources lets any service "
                    + "that receives a user's token for itself replay it against the MCP server.",
            List.of(new Cwe(287, "Improper Authentication"),
                    new Cwe(345, "Insufficient Verification of Data Authenticity")));

    private TokenAudienceDescriptor() {
    }
}
