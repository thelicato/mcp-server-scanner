package com.mcpscanner.checks.catalog.nosqlinjection;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;

import java.util.List;
import java.util.Objects;

record Finding(List<Technique> techniques, AuditIssueConfidence confidence, List<HttpRequestResponse> evidence) {

    Finding {
        techniques = List.copyOf(techniques);
        evidence = evidence.stream().filter(Objects::nonNull).toList();
    }
}
