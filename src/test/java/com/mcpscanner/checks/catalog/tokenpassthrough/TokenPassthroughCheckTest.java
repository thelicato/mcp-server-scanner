package com.mcpscanner.checks.catalog.tokenpassthrough;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.api.SettlingLateIssues;
import com.mcpscanner.checks.shared.collaborator.CollaboratorWatch;
import com.mcpscanner.checks.shared.collaborator.FakeCollaborator;
import com.mcpscanner.checks.shared.collaborator.TestWatches;
import com.mcpscanner.checks.shared.redaction.ExchangeRedactor;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.scan.field.McpFieldGenerator;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TokenPassthroughCheckTest {

    private static final String TOKEN = "client-token-7f3a91c2";
    private static final String URL = "http://mcp.example.test/mcp";
    private static final String TOOL_CALL = "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{"
            + "\"name\":\"import_page\",\"arguments\":{\"source_url\":\"https://docs.example.test/a\","
            + "\"mirror\":\"cdn.example.test\",\"note\":\"hello\"}}}";
    private static final String URL_FIELD = "MCP field: params.arguments.source_url";
    private static final String HOST_FIELD = "MCP field: params.arguments.mirror";
    private static final String TEXT_FIELD = "MCP field: params.arguments.note";
    private static final Pattern PAYLOAD_HOST = Pattern.compile("([a-z0-9]+)\\." + Pattern.quote(FakeCollaborator.DOMAIN));

    private final FakeCollaborator collaborator = new FakeCollaborator();
    private final List<HttpRequest> received = new ArrayList<>();

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void reportsTheClientsBearerTokenReachingTheCollaboratorHostAsHighCertain() {
        List<AuditIssue> issues = audit(bearer(), URL_FIELD, forwarding(Map.of("Authorization", "Bearer " + TOKEN)));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP client token forwarded to another host");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.CERTAIN);
            assertThat(issue.detail()).contains("Field: field " + URL_FIELD).contains("the Authorization header");
            assertThat(issue.requestResponses()).hasSize(2);
        });
        assertThat(received).singleElement()
                .satisfies(probe -> assertThat(probe.bodyToString()).contains("\"source_url\":\"https://p1x."));
    }

    @Test
    void redactsTheTokenFromEveryPieceOfEvidence() {
        HttpRequest base = toolCall().withHeader("Authorization", "Bearer " + TOKEN);

        List<AuditIssue> issues = audit(bearer(), base, URL_FIELD, forwarding(Map.of("X-Upstream-Auth", TOKEN)));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.detail()).doesNotContain(TOKEN).contains("the X-Upstream-Auth header");
            assertThat(issue.requestResponses()).allSatisfy(exchange -> {
                String headers = exchange.request().headers().toString();
                assertThat(headers + exchange.request().bodyToString()).doesNotContain(TOKEN);
                assertThat(headers).contains(ExchangeRedactor.REDACTED);
            });
        });
    }

    @Test
    void findsTheTokenInTheQueryString() {
        Server server = request -> callback(request, "http://%s/collect?access_token=" + TOKEN, Map.of());

        assertThat(audit(bearer(), URL_FIELD, server)).singleElement()
                .satisfies(issue -> assertThat(issue.detail()).contains("the URL"));
    }

    @Test
    void staysSilentWhenTheServerFetchesWithItsOwnCredentialOnly() {
        List<AuditIssue> issues = audit(bearer(), URL_FIELD, forwarding(Map.of("Authorization", "Bearer server-own-key-1")));

        assertThat(issues).isEmpty();
        assertThat(received).hasSize(1);
    }

    @Test
    void probesABareHostValueWithABareHost() {
        audit(bearer(), HOST_FIELD, forwarding(Map.of()));

        assertThat(received).singleElement()
                .satisfies(probe -> assertThat(probe.bodyToString()).contains("\"mirror\":\"p1x." + FakeCollaborator.DOMAIN + "\""));
    }

    @Test
    void sendsNothingForAFieldThatTakesNoUrl() {
        assertThat(audit(bearer(), TEXT_FIELD, forwarding(Map.of("Authorization", "Bearer " + TOKEN)))).isEmpty();
        assertThat(received).isEmpty();
    }

    @Test
    void sendsNothingWhenTheScanningUserHasNoCredential() {
        assertThat(audit(NoAuthStrategy::new, URL_FIELD, forwarding(Map.of()))).isEmpty();
        assertThat(received).isEmpty();
    }

    @Test
    void sendsNothingWithoutCollaborator() {
        TokenPassthroughCheck check = new TokenPassthroughCheck(McpEventLog.noop(), bearer(),
                TestWatches.immediate(java.util.Optional::empty), (reporting, issues) -> { },
                BurpNativeJsonRpcFields.ABSENT);

        assertThat(check.audit(exchange(toolCall()), field(toolCall(), URL_FIELD), http(forwarding(Map.of()))))
                .isEmpty();
        assertThat(received).isEmpty();
    }

    @Test
    void reportsAFieldOnceUntilTheConnectionChanges() {
        CollaboratorWatch watch = TestWatches.immediate(collaborator);
        SettlingLateIssues late = new SettlingLateIssues(watch);
        TokenPassthroughCheck check = new TokenPassthroughCheck(McpEventLog.noop(), bearer(), watch, late,
                BurpNativeJsonRpcFields.ABSENT);
        Http http = http(forwarding(Map.of("Authorization", "Bearer " + TOKEN)));

        check.audit(exchange(toolCall()), field(toolCall(), URL_FIELD), http);
        assertThat(late.settle(check)).hasSize(1);
        check.audit(exchange(toolCall()), field(toolCall(), URL_FIELD), http);
        assertThat(received).hasSize(1);

        check.clearConnectionState();
        check.audit(exchange(toolCall()), field(toolCall(), URL_FIELD), http);
        assertThat(late.settle(check)).hasSize(1);
        assertThat(received).hasSize(2);
    }

    private List<AuditIssue> audit(Supplier<AuthStrategy> auth, String fieldName, Server server) {
        return audit(auth, toolCall(), fieldName, server);
    }

    private List<AuditIssue> audit(Supplier<AuthStrategy> auth, HttpRequest base, String fieldName, Server server) {
        CollaboratorWatch watch = TestWatches.immediate(collaborator);
        SettlingLateIssues late = new SettlingLateIssues(watch);
        TokenPassthroughCheck check = new TokenPassthroughCheck(McpEventLog.noop(), auth, watch, late,
                BurpNativeJsonRpcFields.ABSENT);
        List<AuditIssue> issues = new ArrayList<>(check.audit(exchange(base), field(base, fieldName), http(server)));
        assertThat(issues).as("the audit returns before any Collaborator interaction is read").isEmpty();
        issues.addAll(late.settle(check));
        return issues;
    }

    private static Supplier<AuthStrategy> bearer() {
        return () -> new BearerTokenAuthStrategy(TOKEN);
    }

    private Server forwarding(Map<String, String> headers) {
        return request -> callback(request, "http://%s/", headers);
    }

    private void callback(HttpRequest probe, String urlPattern, Map<String, String> headers) {
        Matcher host = PAYLOAD_HOST.matcher(probe.bodyToString());
        if (!host.find()) {
            return;
        }
        String payloadHost = host.group(0);
        HttpRequest fetch = HttpRequest.httpRequestFromUrl(String.format(urlPattern, payloadHost));
        for (Map.Entry<String, String> header : headers.entrySet()) {
            fetch = fetch.withHeader(header.getKey(), header.getValue());
        }
        collaborator.interactOverHttp(FakeCollaborator.payload(host.group(1)),
                HttpRequestResponse.httpRequestResponse(fetch, null));
    }

    private Http http(Server server) {
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest request = invocation.getArgument(0);
            received.add(request);
            server.handle(request);
            return exchange(request);
        });
        return http;
    }

    private static HttpRequest toolCall() {
        return HttpRequest.httpRequestFromUrl(URL).withMethod("POST")
                .withHeader("Content-Type", "application/json")
                .withHeader("Accept", "application/json, text/event-stream")
                .withBody(TOOL_CALL);
    }

    private static HttpRequestResponse exchange(HttpRequest request) {
        return HttpRequestResponse.httpRequestResponse(request, HttpResponse.httpResponse(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{}}"));
    }

    private static AuditInsertionPoint field(HttpRequest request, String name) {
        return new McpFieldGenerator(() -> true).fieldsOf(request).stream()
                .filter(point -> point.name().equals(name)).findFirst()
                .orElseThrow(() -> new AssertionError("no field " + name));
    }

    @FunctionalInterface
    private interface Server {
        void handle(HttpRequest request);
    }
}
