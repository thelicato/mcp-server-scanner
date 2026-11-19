package com.mcpscanner.checks.catalog.verboseerrors;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.mcp.McpRequestNames;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

final class VerboseErrorsIssues {

    static final String ISSUE_NAME = "MCP verbose error messages";

    private static final String REMEDIATION = new IssueBodyBuilder()
            .paragraph("Catch exceptions at the MCP request boundary and return a short, fixed message that says what "
                    + "was wrong with the request (a JSON-RPC invalid params error, or a tool result with isError), "
                    + "never the exception, its stack trace or the server's file paths.")
            .paragraph("Log the details on the server instead, turn off debug and development modes in production, "
                    + "and validate tool arguments against their input schema before they reach the code that "
                    + "fails.")
            .build();

    private final CheckDescriptor descriptor;

    VerboseErrorsIssues(CheckDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    AuditIssue render(HttpRequest baseRequest, List<Leak> leaks, List<HttpRequestResponse> evidence) {
        List<String> findings = new ArrayList<>();
        for (Leak leak : leaks) {
            String kinds = leak.disclosures().keySet().stream().map(Disclosure::described)
                    .collect(Collectors.joining(", "));
            String examples = leak.disclosures().values().stream().map(matches -> shown(matches.get(0)))
                    .collect(Collectors.joining("; "));
            findings.add(leak.malformation().described() + ": " + kinds + " (for example " + examples + ")");
        }
        AuditIssueSeverity severity = leaks.stream().anyMatch(Leak::disclosesBeyondVersions)
                ? AuditIssueSeverity.LOW : AuditIssueSeverity.INFORMATION;
        String detail = new IssueBodyBuilder()
                .paragraph("Operation: " + new McpRequestNames().nameOf(baseRequest) + ".")
                .paragraph("Malformed copies of the request made the server disclose internal details:")
                .findings(findings)
                .paragraph("None of this text appeared in the baseline reply or in the probe that was sent, and "
                        + "resending the most revealing probe disclosed the same kind of detail again.")
                .paragraph("The requests and responses are, in order: the baseline, each probe that disclosed "
                        + "details, then the resend.")
                .build();
        return AuditIssue.auditIssue(ISSUE_NAME, detail, REMEDIATION, baseRequest.url(), severity,
                descriptor.headlineConfidence(), IssueMetadataRenderer.background(descriptor.issueBackground(),
                        descriptor.cwes(), descriptor.references()),
                REMEDIATION, severity, evidence.toArray(HttpRequestResponse[]::new));
    }

    private static String shown(String match) {
        String flattened = match.replaceAll("\\s+", " ").strip();
        return flattened.length() <= Disclosure.SHOWN_CHARACTERS ? flattened
                : flattened.substring(0, Disclosure.SHOWN_CHARACTERS) + "...";
    }
}
