package com.mcpscanner.checks.catalog.templateinjection;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;

final class TemplateInjectionDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "template-injection",
            "MCP server-side template injection",
            "Appends a multiplication of two random numbers to every MCP field in the expression syntax of common "
                    + "template engines ({{ }}, ${ }, <%= %>, #{ } and { }) and reports a field when the reply "
                    + "carries the product, the same multiplication without template syntax is not evaluated, and "
                    + "two repeats with fresh numbers are evaluated too.",
            CheckKind.INSERTION_POINT,
            AuditIssueSeverity.HIGH,
            AuditIssueConfidence.FIRM,
            true,
            List.of(
                    "https://portswigger.net/web-security/server-side-template-injection",
                    "https://cwe.mitre.org/data/definitions/1336.html",
                    "https://modelcontextprotocol.io/specification/2025-06-18/server/tools#security-considerations"),
            "MCP tools often render text through a template engine: notification bodies, email signatures, "
                    + "report headers or prompt templates. When a server builds the template source from a tool "
                    + "argument instead of passing the argument as a template variable, any client that can call "
                    + "the tool, including an agent steered by untrusted content, can run template expressions. "
                    + "Most engines then expose enough of the host language to read files, environment variables "
                    + "and secrets, or to run commands.",
            List.of(new Cwe(1336, "Improper Neutralization of Special Elements Used in a Template Engine"),
                    new Cwe(94, "Improper Control of Generation of Code ('Code Injection')")));

    private TemplateInjectionDescriptor() {
    }
}
