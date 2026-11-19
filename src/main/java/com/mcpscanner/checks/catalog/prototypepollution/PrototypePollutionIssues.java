package com.mcpscanner.checks.catalog.prototypepollution;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.mcp.McpRequestNames;

final class PrototypePollutionIssues {

    static final String ISSUE_NAME = "MCP server-side prototype pollution";

    private static final String REMEDIATION = new IssueBodyBuilder()
            .paragraph("Merge request values only into objects created with Object.create(null), or use a Map, and "
                    + "refuse or drop the keys __proto__, constructor and prototype before any recursive merge, "
                    + "clone or path assignment. Upgrade merge libraries (lodash 4.17.12 and later, for example) "
                    + "and validate tool arguments against their input schema with additional properties refused.")
            .paragraph("Restart the server process to remove the property the scanner added, and consider "
                    + "Object.freeze(Object.prototype) at start-up or running Node.js with "
                    + "--disable-proto=delete.")
            .build();

    private final CheckDescriptor descriptor;

    PrototypePollutionIssues(CheckDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    AuditIssue render(Finding finding, HttpRequest baseRequest, String fieldName) {
        String detail = new IssueBodyBuilder()
                .paragraph("Operation: " + new McpRequestNames().nameOf(baseRequest) + "; field: " + fieldName + ".")
                .paragraph("The scanner added " + finding.technique().described(finding.first()) + " beside the "
                        + "field and then resent the unmodified request. That later reply contained "
                        + finding.first().value() + ", so the property reached an object the request never set: "
                        + "the server merged the key into Object.prototype.")
                .paragraph("The same nesting under an ordinary key did not reach the next clean reply, so the server "
                        + "does not simply remember earlier arguments, and a repeat with a fresh random property "
                        + "reached the following clean reply too. The scanner's properties stay on the server until "
                        + "its process restarts.")
                .paragraph("The requests and responses are, in order: the baseline, the polluting request and the "
                        + "clean resend that showed the property, the ordinary-key control and its clean resend, then "
                        + "the repeat and its clean resend.")
                .build();
        return AuditIssue.auditIssue(ISSUE_NAME, detail, REMEDIATION, baseRequest.url(), AuditIssueSeverity.HIGH,
                descriptor.headlineConfidence(), IssueMetadataRenderer.background(descriptor.issueBackground(),
                        descriptor.cwes(), descriptor.references()),
                REMEDIATION, AuditIssueSeverity.HIGH, finding.evidence().toArray(HttpRequestResponse[]::new));
    }
}
