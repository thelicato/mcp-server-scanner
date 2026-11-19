package com.mcpscanner.integration;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.core.oauth.AuthorizationApproval;
import com.mcpscanner.auth.oauth.CallbackListenerFactory;
import com.mcpscanner.auth.oauth.OAuthAuthorizationFlow;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.auth.oauth.OAuthSession;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate;
import com.mcpscanner.checks.api.AccessLedger;
import com.mcpscanner.checks.api.CheckCatalog;
import com.mcpscanner.checks.api.CheckRunner;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.checks.api.PrincipalListings;
import com.mcpscanner.checks.api.McpCheck;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.scan.McpInsertionPointProvider;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RecordingRealHttp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
class TokenAudienceCheckIT {

    private static final String CHECK_ID = "token-audience";
    private static final String ISSUE = "MCP server accepts a token issued for another resource";
    private static final SuspiciousDestinationGate ALLOW_LOOPBACK =
            (url, purpose) -> SuspiciousDestinationGate.Decision.allow();

    @BeforeEach
    void installFactory() {
        MontoyaTestFactory.install();
    }

    @ParameterizedTest(name = "with a {0} client")
    @EnumSource(Client.class)
    void firesWhenTheServerAcceptsTokensForAnyAudience(Client client) throws Exception {
        List<AuditIssue> issues = runAgainst("jwt_wrong_audience=vulnerable", client);

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(ISSUE);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.CERTAIN);
            assertThat(issue.detail()).doesNotContain("confidential-secret");
        });
    }

    @ParameterizedTest(name = "with a {0} client")
    @EnumSource(Client.class)
    void staysSilentWhenTheServerChecksTheAudience(Client client) throws Exception {
        assertThat(runAgainst("jwt_wrong_audience=safe", client)).isEmpty();
    }

    private List<AuditIssue> runAgainst(String vulnerabilityMode, Client client) throws Exception {
        try (McpCheckItSupport.RunningServer server = McpCheckItSupport.startServer(
                "--default-mode", "safe", "--consent", "auto", "--vuln", vulnerabilityMode)) {
            URI issuer = URI.create("http://" + McpCheckItSupport.HOST + ":" + server.port());
            URI resource = URI.create(McpCheckItSupport.mcpEndpoint(server.port()));
            RecordingRealHttp http = new RecordingRealHttp(McpCheckItSupport.realHttpClient());
            OAuthAuthCodeStrategy strategy = login(http, issuer, resource, client);
            McpCheck check = CheckCatalog.discover(new CheckServices(McpEventLog.noop(), () -> strategy,
                    Optional::empty, Optional::empty,
                PrincipalRoster::empty, AccessLedger.noop(), PrincipalListings.unknown())).find(CHECK_ID).orElseThrow();
            HttpRequestResponse base = toolsList(http, resource, strategy);
            assertThat(base.response().statusCode()).isEqualTo((short) 200);

            List<AuditIssue> issues = new CheckRunner(http, new McpInsertionPointProvider()::provideInsertionPoints)
                    .run(check, List.of(base));

            assertThat(toolsList(http, resource, strategy).response().statusCode())
                    .as("the live session still works after the check").isEqualTo((short) 200);
            return issues;
        }
    }

    private static OAuthAuthCodeStrategy login(RecordingRealHttp http, URI issuer, URI resource, Client client) {
        OAuthAuthorizationFlow flow = new OAuthAuthorizationFlow(CallbackListenerFactory.defaultFactory(),
                TokenAudienceCheckIT::followAutoConsent, Clock.systemUTC(), ALLOW_LOOPBACK,
                McpEventLog.noop(), http);
        OAuthClientHints hints = new OAuthClientHints(issuer, List.of("mcp:tools"), client.clientId, client.secret,
                client.clientId == null, 0, Duration.ofSeconds(20));
        OAuthSession session = flow.connect(resource, hints);
        return new OAuthAuthCodeStrategy(issuer, session.clientId(), session.sharedSession(), Clock.systemUTC(),
                McpEventLog.noop(), ignored -> AuthorizationApproval.REQUIRE_PROMPT, session.registrationMode());
    }

    private static HttpRequestResponse toolsList(RecordingRealHttp http, URI resource, OAuthAuthCodeStrategy strategy) {
        HttpRequestResponse initialize = http.sendRequest(mcpRequest(resource, strategy,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\","
                        + "\"capabilities\":{},\"clientInfo\":{\"name\":\"it\",\"version\":\"1\"}}}"));
        String sessionId = initialize.response().headerValue("Mcp-Session-Id");
        HttpRequest list = mcpRequest(resource, strategy, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}");
        return http.sendRequest(sessionId == null ? list : list.withHeader("Mcp-Session-Id", sessionId));
    }

    private static HttpRequest mcpRequest(URI resource, OAuthAuthCodeStrategy strategy, String body) {
        return HttpRequest.httpRequestFromUrl(resource.toString()).withMethod("POST")
                .withHeader("Content-Type", "application/json")
                .withHeader("Accept", "application/json, text/event-stream")
                .withHeader("Authorization", strategy.headers().get("Authorization"))
                .withBody(body);
    }

    private static void followAutoConsent(URI authorizationUri) {
        new Thread(() -> {
            try {
                HttpClient client = McpCheckItSupport.realHttpClient();
                HttpResponse<Void> authorize = client.send(java.net.http.HttpRequest.newBuilder(authorizationUri)
                        .GET().timeout(Duration.ofSeconds(10)).build(), HttpResponse.BodyHandlers.discarding());
                String callback = authorize.headers().firstValue("location").orElseThrow();
                client.send(java.net.http.HttpRequest.newBuilder(URI.create(callback)).GET()
                        .timeout(Duration.ofSeconds(10)).build(), HttpResponse.BodyHandlers.discarding());
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }).start();
    }

    enum Client {
        CONFIDENTIAL("confidential-client", "confidential-secret"),
        PUBLIC_DCR(null, null);

        private final String clientId;
        private final String secret;

        Client(String clientId, String secret) {
            this.clientId = clientId;
            this.secret = secret;
        }
    }
}
