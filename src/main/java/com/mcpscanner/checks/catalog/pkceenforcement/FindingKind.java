package com.mcpscanner.checks.catalog.pkceenforcement;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

enum FindingKind {

    CHALLENGE_NOT_REQUIRED(
            "MCP OAuth authorization code issued without PKCE",
            AuditIssueSeverity.MEDIUM,
            AuditIssueConfidence.CERTAIN,
            "The authorization server issued a code for a request with no code_challenge, and its token endpoint "
                    + "exchanged the code for a token without any code_verifier.",
            "Require a code_challenge with method S256 on every authorization request and refuse requests without "
                    + "one with error=invalid_request."),
    VERIFIER_NOT_CHECKED(
            "MCP OAuth PKCE code_verifier not checked",
            AuditIssueSeverity.MEDIUM,
            AuditIssueConfidence.CERTAIN,
            "The authorization server issued a code for an S256 code_challenge, and its token endpoint exchanged "
                    + "the code for a token with a code_verifier that does not match the challenge.",
            "Store the code_challenge with each authorization code and refuse to redeem the code unless "
                    + "BASE64URL(SHA256(code_verifier)) equals it."),
    PLAIN_ACCEPTED(
            "MCP OAuth plain PKCE method accepted",
            AuditIssueSeverity.LOW,
            AuditIssueConfidence.CERTAIN,
            "The authorization server does not advertise the plain PKCE method, yet it issued a code for a plain "
                    + "code_challenge and redeemed it. With plain, the challenge is the verifier itself, so anyone "
                    + "who sees the authorization request can redeem the code.",
            "Accept only code_challenge_method=S256."),
    METADATA(
            "MCP OAuth PKCE support not advertised as required",
            AuditIssueSeverity.INFORMATION,
            AuditIssueConfidence.CERTAIN,
            "The authorization server metadata does not advertise PKCE the way MCP clients require.",
            "List S256, and only S256, in code_challenge_methods_supported in the authorization server metadata, "
                    + "and enforce it.");

    private final String issueName;
    private final AuditIssueSeverity severity;
    private final AuditIssueConfidence confidence;
    private final String observation;
    private final String remediation;

    FindingKind(String issueName, AuditIssueSeverity severity, AuditIssueConfidence confidence, String observation,
                String remediation) {
        this.issueName = issueName;
        this.severity = severity;
        this.confidence = confidence;
        this.observation = observation;
        this.remediation = remediation;
    }

    String issueName() {
        return issueName;
    }

    AuditIssueSeverity severity() {
        return severity;
    }

    AuditIssueConfidence confidence() {
        return confidence;
    }

    String observation() {
        return observation;
    }

    String remediation() {
        return remediation;
    }
}
