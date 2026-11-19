package com.mcpscanner.checks.catalog.tooldefinitiondrift;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.checks.shared.redaction.ExchangeRedactor;

import java.util.List;
import java.util.Set;

final class ToolDefinitionDriftIssues {

    static final String REDEFINED = "MCP tool redefined during a session";
    static final String DIFFERS_BETWEEN_USERS = "MCP tool described differently to another user";

    private static final String REDEFINED_REMEDIATION = "Keep a tool's description, title, annotations and schemas "
            + "fixed for the life of a session. Ship a changed definition under a new tool name or version, "
            + "announce it with notifications/tools/list_changed, and have clients ask the user to approve the "
            + "changed definition before calling it again. Find out where the new definition came from: a "
            + "definition that changes once the tool has been used is the pattern of a rug pull.";
    private static final String DIFFERS_REMEDIATION = "Serve every user the same definition of a tool, and control "
            + "access by which tools are listed and callable rather than by rewording them. If a description must "
            + "vary between users, review every variant, because an approval given for one user's definition "
            + "does not cover what another user's client is told.";

    private final CheckDescriptor descriptor;

    ToolDefinitionDriftIssues(CheckDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    AuditIssue redefined(String baseUrl, String tool, boolean announced, List<DefinitionChange> changes,
                         List<HttpRequestResponse> evidence) {
        String detail = new IssueBodyBuilder()
                .paragraph("The scanner opened its own MCP session and listed the tools twice; the fields below "
                        + "were the same in both listings. It then called " + tool + " once with the scanned "
                        + "arguments and listed the tools again: these fields had changed, and a further listing "
                        + "showed the same changed definition.")
                .findings(changes.stream().map(DefinitionChange::describe).toList())
                .paragraph(announced
                        ? "The server announced the change with notifications/tools/list_changed, so a client "
                                + "that refreshes its tool list picks up the new definition, usually without "
                                + "asking the user to approve it again."
                        : "The server sent no notifications/tools/list_changed on the replies to the call or the "
                                + "later listing, so the change was silent: a client that keeps its first "
                                + "listing would not notice it, one that lists again would use it unreviewed.")
                .build();
        return issue(REDEFINED, detail, REDEFINED_REMEDIATION, baseUrl, descriptor.headlineSeverity(),
                descriptor.headlineConfidence(), evidence);
    }

    AuditIssue differsBetweenUsers(String baseUrl, String userName, List<DefinitionChange> changes,
                                   List<HttpRequestResponse> evidence, Set<String> userSecrets) {
        String detail = new IssueBodyBuilder()
                .paragraph("The scanner listed the tools in two separate sessions as the scanning user and once as "
                        + "the compared user " + userName + ". Each field below was the same in both of the "
                        + "scanning user's sessions but was different for " + userName + " (shown as the scanning "
                        + "user's value, then " + userName + "'s).")
                .findings(changes.stream().map(DefinitionChange::describe).toList())
                .paragraph("A server can legitimately personalise a description, so review whether the difference "
                        + "changes what the model is told to do or which arguments it sends.")
                .build();
        ExchangeRedactor redactor = new ExchangeRedactor(userSecrets);
        return issue(DIFFERS_BETWEEN_USERS, detail, DIFFERS_REMEDIATION, baseUrl, AuditIssueSeverity.LOW,
                AuditIssueConfidence.FIRM, evidence.stream().map(redactor::redact).toList());
    }

    private AuditIssue issue(String name, String detail, String remediation, String baseUrl,
                             AuditIssueSeverity severity, AuditIssueConfidence confidence,
                             List<HttpRequestResponse> evidence) {
        return AuditIssue.auditIssue(name, detail, remediation, baseUrl, severity, confidence,
                IssueMetadataRenderer.background(descriptor.issueBackground(), descriptor.cwes(),
                        descriptor.references()),
                null, severity, evidence);
    }
}
