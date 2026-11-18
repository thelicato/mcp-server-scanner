package com.mcpscanner.checks.catalog.pkceenforcement;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.checks.shared.redaction.ExchangeRedactor;

import java.util.List;

final class PkceEnforcementIssues {

    private final CheckDescriptor descriptor;

    PkceEnforcementIssues(CheckDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    List<AuditIssue> issues(List<PkceFinding> findings, ExchangeRedactor redactor) {
        return findings.stream().map(finding -> issue(finding, redactor)).toList();
    }

    private AuditIssue issue(PkceFinding finding, ExchangeRedactor redactor) {
        FindingKind kind = finding.kind();
        return AuditIssue.auditIssue(
                kind.issueName(),
                new IssueBodyBuilder().paragraph(kind.observation()).findings(finding.facts()).build(),
                kind.remediation(),
                finding.location().toString(),
                kind.severity(),
                kind.confidence(),
                IssueMetadataRenderer.background(descriptor.issueBackground(), descriptor.cwes(),
                        descriptor.references()),
                null,
                kind.severity(),
                finding.evidence().stream().map(redactor::redact).toList());
    }
}
