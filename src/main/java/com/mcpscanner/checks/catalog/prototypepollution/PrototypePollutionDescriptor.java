package com.mcpscanner.checks.catalog.prototypepollution;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;

final class PrototypePollutionDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "prototype-pollution",
            "MCP server-side prototype pollution",
            "Adds a \"__proto__\" key, then a \"constructor\": {\"prototype\": ...} key, beside every JSON field, "
                    + "carrying a random property, and resends the unmodified request. It reports the field when "
                    + "that later, clean reply shows the random value, the same nesting under an ordinary key does "
                    + "not reach a later reply, and a repeat with a fresh property reaches the next clean reply too.",
            CheckKind.INSERTION_POINT,
            AuditIssueSeverity.HIGH,
            AuditIssueConfidence.FIRM,
            true,
            List.of(
                    "https://portswigger.net/web-security/prototype-pollution/server-side",
                    "https://cwe.mitre.org/data/definitions/1321.html",
                    "https://modelcontextprotocol.io/specification/2025-06-18/server/tools#security-considerations"),
            "Many MCP servers run on Node.js and merge tool arguments into default settings with a recursive merge. "
                    + "JSON.parse turns a \"__proto__\" key into an ordinary property, and a merge that follows it, "
                    + "or constructor.prototype, writes into Object.prototype, which every object in the process "
                    + "inherits. The property then appears in every later request, whoever sends it, until the "
                    + "process restarts, and attackers use such properties to change security decisions, crash the "
                    + "server or reach code execution. The check's own property is random and harmless, but it stays "
                    + "on the server until the process restarts.",
            List.of(new Cwe(1321, "Improperly Controlled Modification of Object Prototype Attributes "
                    + "('Prototype Pollution')")));

    private PrototypePollutionDescriptor() {
    }
}
