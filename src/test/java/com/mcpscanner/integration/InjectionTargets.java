package com.mcpscanner.integration;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.CheckCatalog;
import com.mcpscanner.checks.api.CheckRunner;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;
import com.mcpscanner.scan.McpInsertionPointProvider;
import com.mcpscanner.testutil.RecordingRealHttp;

import java.util.List;

final class InjectionTargets {

    private static final String ALICE = "alice-token";

    private InjectionTargets() {
    }

    static List<AuditIssue> scan(String checkId, String vulnerabilityMode, String tool, String argumentsJson)
            throws Exception {
        try (McpCheckItSupport.RunningServer server = McpCheckItSupport.startServer("--default-mode", "safe",
                "--vuln", vulnerabilityMode)) {
            String sessionId = McpCheckItSupport.initializeSessionWithBearer(server.port(), ALICE);
            HttpRequest call = HttpRequest.httpRequestFromUrl(McpCheckItSupport.mcpEndpoint(server.port()))
                    .withMethod("POST")
                    .withHeader("Content-Type", "application/json")
                    .withHeader("Accept", "application/json, text/event-stream")
                    .withHeader("Authorization", "Bearer " + ALICE)
                    .withHeader("Mcp-Session-Id", sessionId)
                    .withBody("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"" + tool
                            + "\",\"arguments\":" + argumentsJson + "}}");
            RecordingRealHttp http = new RecordingRealHttp(McpCheckItSupport.realHttpClient());
            HttpRequestResponse base = http.sendRequest(call);
            McpCheck check = CheckCatalog.discover(CheckServices.standalone()).find(checkId).orElseThrow();
            return new CheckRunner(http, new McpInsertionPointProvider()::provideInsertionPoints)
                    .run(check, List.of(base));
        }
    }
}
