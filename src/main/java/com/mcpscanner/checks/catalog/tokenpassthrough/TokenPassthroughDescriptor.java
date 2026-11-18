package com.mcpscanner.checks.catalog.tokenpassthrough;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;

final class TokenPassthroughDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "token-passthrough",
            "MCP token passthrough",
            "Places a unique Burp Collaborator address in every MCP field and header that takes a URL or host, "
                    + "then reports when the server's request to that address carries the scanning user's own "
                    + "credential.",
            CheckKind.INSERTION_POINT,
            AuditIssueSeverity.HIGH,
            AuditIssueConfidence.CERTAIN,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices#token-passthrough",
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#token-passthrough",
                    "https://portswigger.net/burp/documentation/collaborator"),
            "The MCP specification forbids token passthrough: an MCP server must not accept a token that was not "
                    + "issued for it, and must not forward the token its client presented to another service. A "
                    + "server that does forwards a credential the client never meant to share. Whoever controls "
                    + "the host it is sent to can replay it against every service that accepts it, and the "
                    + "downstream service cannot tell the MCP server's calls from the client's own. The scanner "
                    + "detects the forwarded credential out of band through Burp Collaborator.",
            List.of(new Cwe(201, "Insertion of Sensitive Information Into Sent Data"),
                    new Cwe(441, "Unintended Proxy or Intermediary ('Confused Deputy')")));

    private TokenPassthroughDescriptor() {
    }
}
