package com.mcpscanner.checks.catalog.templateinjection;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.mcp.McpRequestNames;

final class TemplateInjectionIssues {

    static final String ISSUE_NAME = "MCP server-side template injection";

    private static final String REMEDIATION = new IssueBodyBuilder()
            .paragraph("Never build template source from MCP request values. Keep templates fixed and pass values "
                    + "to them as variables, which the engine renders as text.")
            .paragraph("If users must supply templates, render them in the engine's sandbox with a minimal context, "
                    + "and run the server with the least privilege it needs.")
            .build();

    private final CheckDescriptor descriptor;

    TemplateInjectionIssues(CheckDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    AuditIssue render(Finding finding, HttpRequest baseRequest, String fieldName) {
        Product first = finding.first();
        String detail = new IssueBodyBuilder()
                .paragraph("Operation: " + new McpRequestNames().nameOf(baseRequest) + "; field: " + fieldName + ".")
                .paragraph("Appending " + finding.syntax().wrap(first.expression()) + " to the value returned "
                        + first.value() + ", the product, so the server evaluated the expression as a template. "
                        + "Likely engine: " + finding.syntax().engines() + ".")
                .paragraph("The product did not appear in the baseline reply, the same multiplication appended "
                        + "without template syntax was not evaluated, and two repeats with fresh random numbers "
                        + "returned their products too.")
                .paragraph("The requests and responses are, in order: the baseline, the template expression, the "
                        + "multiplication without template syntax, then the two repeats.")
                .build();
        return AuditIssue.auditIssue(ISSUE_NAME, detail, REMEDIATION, baseRequest.url(), AuditIssueSeverity.HIGH,
                descriptor.headlineConfidence(), IssueMetadataRenderer.background(descriptor.issueBackground(),
                        descriptor.cwes(), descriptor.references()),
                REMEDIATION, AuditIssueSeverity.HIGH, finding.evidence().toArray(HttpRequestResponse[]::new));
    }
}
