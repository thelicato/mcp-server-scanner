package com.mcpscanner.checks.catalog.tooldefinitiondrift;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.api.HostSettlement;
import com.mcpscanner.checks.api.HostTrial;
import com.mcpscanner.checks.api.ImplementedKind;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalRole;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.checks.shared.redaction.ExchangeRedactor;
import com.mcpscanner.checks.shared.session.OutsideBurpConnections;
import com.mcpscanner.http.CertificateValidation;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class ToolDefinitionDriftCheckTest {

    private static final String PREFIX = "Scan check: tool-definition-drift - ";
    private static final String PRIMARY_TOKEN = "Bearer primary-token-1";
    private static final String CAROL_TOKEN = "Bearer carol-token-2";

    private final McpEventLog eventLog = new McpEventLog(null);
    private PrincipalRoster roster = PrincipalRoster.of(Principal.primary(() -> Map.of()), List.of());
    private Optional<HttpService> legacySse = Optional.empty();

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void declaresAHostCheckWithItsCatalogId() {
        ToolDefinitionDriftCheck check = check();

        assertThat(check.descriptor().id()).isEqualTo("tool-definition-drift");
        assertThat(check.descriptor().kind()).isEqualTo(CheckKind.HOST);
        assertThat(ImplementedKind.of(check)).isEqualTo(CheckKind.HOST);
        assertThat(check.descriptor().cwes()).isNotEmpty();
    }

    @Test
    void reportsAToolRedefinedAfterItsCallAndAnnounced() {
        DriftServer server = DriftServer.rugPull().streamingAndAnnouncing();

        List<AuditIssue> issues = check().audit(DriftServer.toolCall(), server.http);

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(ToolDefinitionDriftIssues.REDEFINED);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("convert description", "convert inputSchema",
                    "announced the change with notifications/tools/list_changed", "&lt;IMPORTANT&gt;")
                    .doesNotContain("<IMPORTANT>");
            assertThat(issue.requestResponses()).hasSize(3);
        });
        assertThat(server.methods()).containsExactly("initialize", "notifications/initialized", "tools/list",
                "tools/list", "tools/call", "tools/list", "tools/list", "DELETE");
    }

    @Test
    void reportsASilentRedefinition() {
        List<AuditIssue> issues = check().audit(DriftServer.toolCall(), DriftServer.rugPull().http);

        assertThat(issues).singleElement().satisfies(issue ->
                assertThat(issue.detail()).contains("sent no notifications/tools/list_changed"));
    }

    @Test
    void reportsARedefinitionOnALaterPage() {
        DriftServer server = DriftServer.serving(view -> List.of(DriftServer.HISTORY,
                view.called() ? DriftServer.POISONED : DriftServer.CONVERT)).pagedBy(1);

        assertThat(check().audit(DriftServer.toolCall(), server.http))
                .extracting(AuditIssue::name).containsExactly(ToolDefinitionDriftIssues.REDEFINED);
    }

    @Test
    void replaysAModernSeedWithItsClientMetadataButWithoutTheProtocolEnvelope() {
        DriftServer server = DriftServer.rugPull();
        HttpRequestResponse modern = DriftServer.seed("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"convert\",\"arguments\":{\"amount\":10},\"_meta\":{"
                + "\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"progressToken\":\"p-1\"}}}");

        assertThat(check().audit(modern, server.http)).hasSize(1);
        assertThat(server.requests()).filteredOn(request -> request.body().contains("tools/call"))
                .singleElement().satisfies(request -> assertThat(request.body())
                        .contains("\"progressToken\":\"p-1\"", "\"amount\":10")
                        .doesNotContain("2026-07-28"));
    }

    @Test
    void anAddedToolIsNotARedefinition() {
        DriftServer server = DriftServer.serving(view -> view.called()
                ? List.of(DriftServer.CONVERT, DriftServer.HISTORY) : List.of(DriftServer.CONVERT))
                .streamingAndAnnouncing();

        assertThat(check().audit(DriftServer.toolCall(), server.http)).isEmpty();
        assertThat(log()).contains(PREFIX + "decision: no tool definition changed after calling convert "
                + "(the server announced a tool list change)");
    }

    @Test
    void aStableServerReleasesTheSeedSoAnotherToolCallCanTry() {
        DriftServer server = DriftServer.stable();

        assertThat(sessionTrial().run(DriftServer.toolCall(), server.http).settlement())
                .isEqualTo(HostSettlement.UNSUITABLE_SEED);
        assertThat(server.methods()).endsWith("DELETE");
    }

    @Test
    void aDescriptionThatChangesOnEveryListingIsVolatileNotDrift() {
        DriftServer server = DriftServer.serving(view -> List.of("{\"name\":\"convert\",\"description\":"
                + "\"Rates as of listing " + view.listing() + "\",\"inputSchema\":{\"type\":\"object\"}"
                + DriftServer.READ_ONLY + "}"));

        assertThat(check().audit(DriftServer.toolCall(), server.http)).isEmpty();
        assertThat(log()).anyMatch(line -> line.contains("1 field(s) changed between two plain listings"));
    }

    @Test
    void aRedefinitionThatRevertsOnTheNextListingIsNotReported() {
        DriftServer server = DriftServer.serving(view -> List.of(view.called() && view.listing() == 3
                ? DriftServer.POISONED : DriftServer.CONVERT));

        assertThat(check().audit(DriftServer.toolCall(), server.http)).isEmpty();
        assertThat(log()).contains(PREFIX + "decision: definitions changed after calling convert but not on the "
                + "next listing");
    }

    @Test
    void aToolThatMayWriteIsNeverReplayed() {
        String writing = DriftServer.CONVERT.replace(DriftServer.READ_ONLY, "");
        DriftServer server = DriftServer.serving(view -> List.of(writing));

        assertThat(sessionTrial().run(DriftServer.toolCall(), server.http).settlement())
                .isEqualTo(HostSettlement.UNSUITABLE_SEED);
        assertThat(server.methods()).doesNotContain("tools/call").endsWith("DELETE");
        assertThat(log()).anyMatch(line -> line.contains("not annotated read-only"));
    }

    @Test
    void aSeedThatIsNotAToolCallLeavesTheSessionTrialOut() {
        HttpRequestResponse list = DriftServer.seed("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/list\"}");

        assertThat(sessionTrial().whyNotApplicable(list)).isPresent();
        assertThat(check().appliesTo(list)).isFalse();
    }

    @Test
    void theLegacySseTransportIsNotApplicable() {
        legacySse = Optional.of(HttpService.httpService("target.test", 80, false));

        assertThat(check().appliesTo(DriftServer.toolCall())).isFalse();
    }

    @Test
    void aServerListingNoToolsSettlesAndSaysWhy() {
        DriftServer server = DriftServer.serving(view -> List.of());

        assertThat(sessionTrial().run(DriftServer.toolCall(), server.http).settlement())
                .isEqualTo(HostSettlement.SETTLED);
        assertThat(log()).anyMatch(line -> line.contains("the server lists no tools"));
    }

    @Test
    void aRateLimitedListingStopsAndSaysSo() {
        DriftServer server = DriftServer.rugPull().rateLimitingListings();

        assertThat(check().audit(DriftServer.toolCall(), server.http)).isEmpty();
        assertThat(log()).anyMatch(line -> line.contains("rate limited"));
    }

    @Test
    void aRateLimitedHandshakeStopsBothTrialsAndSaysSo() {
        withCarol();
        DriftServer server = DriftServer.rugPull().rateLimitingHandshakes();

        assertThat(sessionTrial().run(DriftServer.toolCall(), server.http).settlement())
                .isEqualTo(HostSettlement.SETTLED);
        assertThat(userTrial().run(DriftServer.toolCall(), server.http).settlement())
                .isEqualTo(HostSettlement.SETTLED);
        assertThat(log()).filteredOn(line -> line.contains("rate limited")).hasSize(2);
    }

    @Test
    void anUnansweredReplayIsInconclusive() {
        DriftServer server = DriftServer.rugPull().leavingCallsUnanswered();

        assertThat(sessionTrial().run(DriftServer.toolCall(), server.http).settlement())
                .isEqualTo(HostSettlement.INCONCLUSIVE);
    }

    @Test
    void reportsAToolDescribedDifferentlyToAComparedUserAndRedactsTheirCredentials() {
        withCarol();
        DriftServer server = DriftServer.serving(view -> List.of(view.authorization().equals(CAROL_TOKEN)
                ? DriftServer.POISONED : DriftServer.CONVERT));

        List<AuditIssue> issues = userTrial().run(DriftServer.toolCall(), server.http).issues();

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(ToolDefinitionDriftIssues.DIFFERS_BETWEEN_USERS);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
            assertThat(issue.detail()).contains("Carol", "convert description");
            assertThat(issue.requestResponses()).hasSize(2);
            assertThat(issue.requestResponses().get(0).request().headerValue("Authorization"))
                    .isEqualTo(PRIMARY_TOKEN);
            assertThat(issue.requestResponses().get(1).request().headerValue("Authorization"))
                    .isEqualTo(ExchangeRedactor.REDACTED);
        });
        assertThat(server.requests()).filteredOn(request -> request.body().contains("tools/list"))
                .extracting(request -> request.headers().get("Authorization"))
                .containsExactly(PRIMARY_TOKEN, PRIMARY_TOKEN, CAROL_TOKEN);
    }

    @Test
    void aDescriptionThatDiffersPerSessionIsNotAPerUserDifference() {
        withCarol();
        DriftServer server = DriftServer.serving(view -> List.of("{\"name\":\"convert\",\"description\":"
                + "\"Convert in session " + view.sessionId() + "\",\"inputSchema\":{\"type\":\"object\"}}"));

        assertThat(userTrial().run(DriftServer.toolCall(), server.http).issues()).isEmpty();
    }

    @Test
    void theUserTrialIsNotApplicableWithoutComparedUsers() {
        assertThat(userTrial().whyNotApplicable(DriftServer.toolCall()))
                .hasValueSatisfying(reason -> assertThat(reason.toString()).contains("no compared user"));
    }

    @Test
    void theUserTrialRunsFromASeedThatIsNotAToolCall() {
        withCarol();
        HttpRequestResponse list = DriftServer.seed("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/list\"}");

        assertThat(userTrial().whyNotApplicable(list)).isEmpty();
        assertThat(check().appliesTo(list)).isTrue();
    }

    private void withCarol() {
        roster = PrincipalRoster.of(Principal.primary(() -> Map.of("Authorization", PRIMARY_TOKEN)),
                List.of(new Principal("carol", "Carol", PrincipalRole.LOWER,
                        () -> Map.of("Authorization", CAROL_TOKEN), Optional.empty(), Map.of())));
    }

    private ToolDefinitionDriftCheck check() {
        return new ToolDefinitionDriftCheck(eventLog, () -> () -> Map.of("Authorization", PRIMARY_TOKEN),
                () -> roster, () -> legacySse, new OutsideBurpConnections(CertificateValidation.enforced()));
    }

    private HostTrial sessionTrial() {
        return check().trials().get(0);
    }

    private HostTrial userTrial() {
        return check().trials().get(1);
    }

    private List<String> log() {
        return eventLog.snapshot().stream().map(McpEventLog.LogEntry::message).toList();
    }
}
