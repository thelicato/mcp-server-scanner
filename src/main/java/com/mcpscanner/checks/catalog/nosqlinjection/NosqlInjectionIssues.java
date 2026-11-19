package com.mcpscanner.checks.catalog.nosqlinjection;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.mcp.McpRequestNames;

final class NosqlInjectionIssues {

    static final String ISSUE_NAME = "MCP NoSQL injection";

    private static final String OBSERVATION = "For each technique, the probe's reply differed from the reply to a "
            + "plain random value, while a falsifier of the same shape that should match nothing got exactly the "
            + "random value's reply. Text the server reflected from the probes was masked before comparing, so a "
            + "reflection cannot explain the difference. The baseline resent unchanged, and two repeats of the first "
            + "technique with fresh random values separated the same way.";
    private static final String TENTATIVE_NOTE = "Only one technique separated the replies, so the finding is "
            + "tentative: confirm that the value reaches a database query.";
    private static final String REMEDIATION = new IssueBodyBuilder()
            .paragraph("Check the JSON type of every MCP request value before it reaches a query, and refuse objects "
                    + "and arrays where a string or number is expected, or strip keys that start with $ (as "
                    + "mongo-sanitize and Mongoose's sanitizeFilter do).")
            .paragraph("Never build $where, $function or $accumulator JavaScript from request values; express the "
                    + "condition with ordinary query operators and pass the value as their operand.")
            .build();

    private final CheckDescriptor descriptor;

    NosqlInjectionIssues(CheckDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    AuditIssue render(Finding finding, HttpRequest baseRequest, String fieldName) {
        IssueBodyBuilder body = new IssueBodyBuilder()
                .paragraph("Operation: " + new McpRequestNames().nameOf(baseRequest) + "; field: " + fieldName + ".")
                .findings(finding.techniques().stream().map(Technique::described).toList())
                .paragraph(OBSERVATION);
        if (finding.confidence() == AuditIssueConfidence.TENTATIVE) {
            body.paragraph(TENTATIVE_NOTE);
        }
        String detail = body.paragraph("The requests and responses are, in order: the baseline, then for each "
                + "technique the random value, the probe and the falsifier, then two confirmation rounds each holding "
                + "the baseline resent, a fresh random value, the probe and the falsifier.").build();
        return AuditIssue.auditIssue(ISSUE_NAME, detail, REMEDIATION, baseRequest.url(), AuditIssueSeverity.HIGH,
                finding.confidence(), IssueMetadataRenderer.background(descriptor.issueBackground(),
                        descriptor.cwes(), descriptor.references()),
                REMEDIATION, AuditIssueSeverity.HIGH, finding.evidence().toArray(HttpRequestResponse[]::new));
    }
}
