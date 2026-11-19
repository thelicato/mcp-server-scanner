package com.mcpscanner.checks.catalog.tokenaudience;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.catalog.tokenaudience.AudienceProbe.Outcome;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.checks.shared.redaction.ExchangeRedactor;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

final class TokenAudienceIssues {

    static final String CONFIRMED = "MCP server accepts a token issued for another resource";
    static final String UNCONFIRMED = "MCP server accepts a token requested for another resource";
    private static final String REMEDIATION = "Accept only access tokens whose audience is this MCP server: check the "
            + "aud claim of a JWT, or the audience your authorization server's introspection endpoint reports for an "
            + "opaque token, and refuse every other token with HTTP 401. Have the authorization server honour the RFC "
            + "8707 resource parameter so each token names the server it was issued for.";

    private final CheckDescriptor descriptor;

    TokenAudienceIssues(CheckDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    AuditIssue accepted(String mcpEndpoint, URI foreign, Outcome outcome) {
        boolean proven = outcome.audience().isPresent();
        List<String> facts = new ArrayList<>();
        facts.add("Refresh of the scanning user's grant with resource=" + foreign + ": an access token was issued");
        outcome.audience().ifPresent(audience -> facts.add("The token is a JWT whose aud is " + audience.audiences()));
        facts.add("tools/list with that token: answered like the user's own token, while no token and a malformed "
                + "token were refused");
        IssueBodyBuilder body = new IssueBodyBuilder()
                .paragraph(proven
                        ? "The MCP server accepted an access token that its authorization server issued for an "
                                + "unrelated resource."
                        : "The MCP server accepted an opaque access token requested for an unrelated resource.")
                .findings(facts);
        if (!proven) {
            body.paragraph("The token is opaque, so the scanner cannot tell whether the authorization server honoured "
                    + "the resource parameter or issued an ordinary token for this server. Confirm through token "
                    + "introspection before relying on this.");
        }
        ExchangeRedactor redactor = new ExchangeRedactor(outcome.secrets());
        AuditIssueSeverity severity = proven ? AuditIssueSeverity.HIGH : AuditIssueSeverity.INFORMATION;
        return AuditIssue.auditIssue(proven ? CONFIRMED : UNCONFIRMED, body.build(), REMEDIATION, mcpEndpoint,
                severity, proven ? AuditIssueConfidence.CERTAIN : AuditIssueConfidence.TENTATIVE,
                IssueMetadataRenderer.background(descriptor.issueBackground(), descriptor.cwes(),
                        descriptor.references()),
                null, severity, outcome.evidence().stream().map(redactor::redact).toList());
    }
}
