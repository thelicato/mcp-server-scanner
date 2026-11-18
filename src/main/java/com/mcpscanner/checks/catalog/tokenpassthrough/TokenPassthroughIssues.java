package com.mcpscanner.checks.catalog.tokenpassthrough;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.checks.shared.redaction.ExchangeRedactor;

import java.util.List;

final class TokenPassthroughIssues {

    static final String NAME = "MCP client token forwarded to another host";
    private static final String REMEDIATION = "Never forward the credential an MCP client presented to another "
            + "service. Call downstream services with a credential issued to the MCP server itself, for example "
            + "one obtained through OAuth token exchange for that service's audience, and connect only to the "
            + "hosts the server is configured for.";

    private final CheckDescriptor descriptor;

    TokenPassthroughIssues(CheckDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    AuditIssue forwarded(HttpRequestResponse base, String fieldLocation, String probeValue, HttpRequestResponse probe,
                         HttpRequest callback, List<String> places, ExchangeRedactor redactor) {
        String detail = new IssueBodyBuilder()
                .paragraph("Field: " + fieldLocation)
                .paragraph("The scanner put " + probeValue + " in this field. The server then sent an HTTP request "
                        + "to that Burp Collaborator address carrying the scanning user's own credential in:")
                .findings(places)
                .paragraph("The credential is redacted in the evidence. The second request is the one the server "
                        + "sent to Burp Collaborator.")
                .build();
        HttpRequestResponse forwarded = redactor.redact(HttpRequestResponse.httpRequestResponse(callback, null));
        return AuditIssue.auditIssue(NAME, detail, REMEDIATION, base.request().url(), descriptor.headlineSeverity(),
                descriptor.headlineConfidence(), IssueMetadataRenderer.background(descriptor.issueBackground(),
                        descriptor.cwes(), descriptor.references()),
                null, descriptor.headlineSeverity(), redactor.redact(probe), forwarded);
    }
}
