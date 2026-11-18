package com.mcpscanner.checks.catalog.pkceenforcement;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;

final class PkceEnforcementDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "pkce-enforcement",
            "MCP OAuth PKCE enforcement",
            "Reads the MCP server's authorization server metadata and reports when it does not advertise the S256 "
                    + "PKCE method, or advertises plain. When the server offers anonymous dynamic client "
                    + "registration, registers a throwaway public client and requests authorization codes with no "
                    + "user session (following at most five same-origin redirects): one with no code_challenge, "
                    + "one with an S256 challenge redeemed with the wrong code_verifier, and, when plain is not "
                    + "advertised, one with a plain challenge. It reports each code the token endpoint exchanges "
                    + "for a token. These code tests run only when the server issues codes without a login. The "
                    + "check never sends the scanner's own credentials to the authorization server, revokes every "
                    + "token it obtains through RFC 7009 when offered, and deletes its probe client through RFC "
                    + "7592 client management when offered.",
            CheckKind.HOST,
            AuditIssueSeverity.MEDIUM,
            AuditIssueConfidence.CERTAIN,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#authorization-code-protection",
                    "https://datatracker.ietf.org/doc/html/rfc7636",
                    "https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.1"),
            "MCP clients are public OAuth clients with no secret, so PKCE is what stops a stolen authorization code "
                    + "from being redeemed by someone else. The MCP authorization specification requires clients "
                    + "to use PKCE with S256 and to refuse an authorization server that does not advertise it. An "
                    + "authorization server must therefore advertise S256, bind each code to the code_challenge "
                    + "sent with it, and refuse to redeem the code without the matching code_verifier.",
            List.of(new Cwe(287, "Improper Authentication"),
                    new Cwe(345, "Insufficient Verification of Data Authenticity")));

    private PkceEnforcementDescriptor() {
    }
}
