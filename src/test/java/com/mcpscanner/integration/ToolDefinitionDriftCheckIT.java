package com.mcpscanner.integration;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.AccessLedger;
import com.mcpscanner.checks.api.CheckCatalog;
import com.mcpscanner.checks.api.CheckRunner;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalListings;
import com.mcpscanner.checks.api.PrincipalRole;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.scan.McpInsertionPointProvider;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RecordingRealHttp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
class ToolDefinitionDriftCheckIT {

    private static final String CHECK_ID = "tool-definition-drift";
    private static final String REDEFINED = "MCP tool redefined during a session";
    private static final String DIFFERS = "MCP tool described differently to another user";
    private static final String ALICE = "Bearer alice-token";

    @BeforeEach
    void installFactory() {
        MontoyaTestFactory.install();
    }

    @ParameterizedTest(name = "with {0} replies")
    @ValueSource(strings = {"json", "sse"})
    void reportsTheRugPullAfterTheFirstCall(String responseMode) throws Exception {
        List<AuditIssue> issues = runAgainst(responseMode, "tool_definition_drift=vulnerable");

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(REDEFINED);
            assertThat(issue.detail()).contains("convert_currency description", "convert_currency inputSchema",
                    "id_rsa");
            assertThat(issue.detail()).contains(responseMode.equals("sse")
                    ? "announced the change with notifications/tools/list_changed"
                    : "sent no notifications/tools/list_changed");
        });
    }

    @ParameterizedTest(name = "with {0} replies")
    @ValueSource(strings = {"json", "sse"})
    void staysSilentWhenTheFirstCallOnlyAddsATool(String responseMode) throws Exception {
        assertThat(runAgainst(responseMode, "tool_definition_drift=safe")).isEmpty();
    }

    @ParameterizedTest(name = "with {0} replies")
    @ValueSource(strings = {"json", "sse"})
    void reportsTheReaderWhoIsToldSomethingElse(String responseMode) throws Exception {
        List<AuditIssue> issues = runAgainst(responseMode, "tool_definition_per_user=vulnerable");

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(DIFFERS);
            assertThat(issue.detail()).contains("carol", "search_tickets description").doesNotContain("bob");
        });
    }

    @ParameterizedTest(name = "with {0} replies")
    @ValueSource(strings = {"json", "sse"})
    void staysSilentWhenEveryUserIsToldTheSame(String responseMode) throws Exception {
        assertThat(runAgainst(responseMode, "tool_definition_per_user=safe")).isEmpty();
    }

    private List<AuditIssue> runAgainst(String responseMode, String vulnerabilityMode) throws Exception {
        try (McpCheckItSupport.RunningServer server = McpCheckItSupport.startServer("--default-mode", "safe",
                "--response-mode", responseMode, "--vuln", vulnerabilityMode)) {
            String endpoint = McpCheckItSupport.mcpEndpoint(server.port());
            RecordingRealHttp http = new RecordingRealHttp(McpCheckItSupport.realHttpClient());
            McpCheck check = CheckCatalog.discover(new CheckServices(McpEventLog.noop(),
                    () -> () -> Map.of("Authorization", ALICE), Optional::empty, Optional::empty,
                    ToolDefinitionDriftCheckIT::roster, AccessLedger.noop(), PrincipalListings.unknown()))
                    .find(CHECK_ID).orElseThrow();
            return new CheckRunner(http, new McpInsertionPointProvider()::provideInsertionPoints)
                    .run(check, List.of(convertCurrency(endpoint)));
        }
    }

    private static PrincipalRoster roster() {
        return PrincipalRoster.of(Principal.primary(() -> Map.of("Authorization", ALICE)), List.of(
                user("bob", PrincipalRole.PEER), user("carol", PrincipalRole.LOWER)));
    }

    private static Principal user(String name, PrincipalRole role) {
        return new Principal(name, name, role, () -> Map.of("Authorization", "Bearer " + name + "-token"),
                Optional.empty(), Map.of());
    }

    private static HttpRequestResponse convertCurrency(String endpoint) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(endpoint).withMethod("POST")
                .withHeader("Content-Type", "application/json")
                .withHeader("Accept", "application/json, text/event-stream")
                .withHeader("Authorization", ALICE)
                .withHeader("MCP-Protocol-Version", "2025-06-18")
                .withBody("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":"
                        + "\"convert_currency\",\"arguments\":{\"amount\":10,\"currency\":\"GBP\"}}}");
        return HttpRequestResponse.httpRequestResponse(request, null);
    }
}
