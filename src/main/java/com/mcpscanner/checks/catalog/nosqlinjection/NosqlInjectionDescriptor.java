package com.mcpscanner.checks.catalog.nosqlinjection;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;

final class NosqlInjectionDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "nosql-injection",
            "MCP NoSQL injection",
            "Replaces every JSON field with MongoDB query operators ({\"$ne\": x}, {\"$regex\": \".*\"}) and "
                    + "breaks out of quoted $where JavaScript with an always-true condition. Each probe is paired "
                    + "with a falsifier of the same shape that should match nothing ({\"$eq\": x}, an always-false "
                    + "condition) and with a plain random value. It reports a field when the probe's reply differs "
                    + "from the random value's, the falsifier's reply equals it, and the separation holds in two "
                    + "repeats with fresh values while the baseline resends unchanged.",
            CheckKind.INSERTION_POINT,
            AuditIssueSeverity.HIGH,
            AuditIssueConfidence.FIRM,
            true,
            List.of(
                    "https://portswigger.net/web-security/nosql-injection",
                    "https://cwe.mitre.org/data/definitions/943.html",
                    "https://modelcontextprotocol.io/specification/2025-06-18/server/tools#security-considerations"),
            "MCP tool arguments arrive as JSON, so a server that copies an argument straight into a MongoDB-style "
                    + "filter receives objects as readily as strings, and an object such as {\"$ne\": \"\"} becomes "
                    + "a query operator that matches every document. A server that concatenates an argument into "
                    + "a $where expression lets the caller append JavaScript. Either way, any client that can call "
                    + "the tool, including an agent steered by untrusted content, can read records it should not "
                    + "see or bypass a lookup that guards access.",
            List.of(new Cwe(943, "Improper Neutralization of Special Elements in Data Query Logic")));

    private NosqlInjectionDescriptor() {
    }
}
