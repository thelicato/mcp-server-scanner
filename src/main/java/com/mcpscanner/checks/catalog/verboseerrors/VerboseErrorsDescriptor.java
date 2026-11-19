package com.mcpscanner.checks.catalog.verboseerrors;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;

final class VerboseErrorsDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "verbose-errors",
            "MCP verbose error messages",
            "Resends every MCP request malformed four ways (params sent as a string, every argument with another "
                    + "JSON type, a 64 KiB string argument and every argument left out) and reports stack "
                    + "traces, server source file paths and framework or runtime versions that appear in the replies "
                    + "but not in the baseline reply or the probe itself, when a resend of the probe discloses the "
                    + "same again.",
            CheckKind.REQUEST,
            AuditIssueSeverity.LOW,
            AuditIssueConfidence.FIRM,
            true,
            List.of(
                    "https://portswigger.net/web-security/information-disclosure",
                    "https://cwe.mitre.org/data/definitions/209.html",
                    "https://modelcontextprotocol.io/specification/2025-06-18/server/tools#error-handling"),
            "An MCP server that returns its internal error details to the client tells an attacker how it is "
                    + "built: stack traces name modules, functions and libraries, file paths show where the code "
                    + "and its dependencies live, and versions point to known vulnerabilities. Tool errors are also "
                    + "read by the model, so the details reach any agent and whatever content steers it. Clients "
                    + "only need a short description of what was wrong with the request.",
            List.of(new Cwe(209, "Generation of Error Message Containing Sensitive Information"),
                    new Cwe(497, "Exposure of Sensitive System Information to an Unauthorized Control Sphere")));

    private VerboseErrorsDescriptor() {
    }
}
