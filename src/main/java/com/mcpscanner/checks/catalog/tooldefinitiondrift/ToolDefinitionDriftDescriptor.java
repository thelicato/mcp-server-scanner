package com.mcpscanner.checks.catalog.tooldefinitiondrift;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;

final class ToolDefinitionDriftDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "tool-definition-drift",
            "MCP tool definition drift",
            "Opens its own MCP session, lists the tools twice as a control, replays the scanned tool call, lists "
                    + "them again and reports a tool whose description, title, annotations or schema changed "
                    + "while the session was in use and stayed changed (a rug pull), noting whether the server "
                    + "announced it with notifications/tools/list_changed. It also lists the tools as every "
                    + "compared user and reports a tool whose definition differs from the one the scanning user "
                    + "was shown, unchanged, in two separate sessions.",
            CheckKind.HOST,
            AuditIssueSeverity.MEDIUM,
            AuditIssueConfidence.FIRM,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/server/tools#list-changed-notification",
                    "https://modelcontextprotocol.io/specification/2025-11-25/server/tools#security-considerations",
                    "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"),
            "An MCP client shows the user a tool's description and schema when the user approves the tool, and "
                    + "the model reads the same description every time it decides how to call it. A server that "
                    + "changes a tool's definition after it has been approved and used (a rug pull) can slip "
                    + "instructions into the model's context or widen the arguments it collects, without the "
                    + "user seeing the change: clients that refresh their tool list after "
                    + "notifications/tools/list_changed rarely ask for approval again. A server that describes "
                    + "the same tool differently to different users can target the change at users whose "
                    + "approvals nobody reviews. Fields that changed between two listings with nothing in "
                    + "between, or between two sessions of the scanning user, are treated as volatile and "
                    + "never reported.",
            List.of(new Cwe(345, "Insufficient Verification of Data Authenticity"),
                    new Cwe(367, "Time-of-check Time-of-use (TOCTOU) Race Condition")));

    private ToolDefinitionDriftDescriptor() {
    }
}
