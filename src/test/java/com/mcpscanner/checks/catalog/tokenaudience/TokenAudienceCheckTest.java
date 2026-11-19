package com.mcpscanner.checks.catalog.tokenaudience;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;

import com.mcpscanner.auth.oauth.TestOAuthStrategies;
import com.mcpscanner.checks.shared.oauth.ScriptedHttp;
import com.mcpscanner.core.oauth.RegistrationMode;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.json;
import static org.assertj.core.api.Assertions.assertThat;

class TokenAudienceCheckTest {

    private static final String ORIGIN = "https://as.example";
    private static final String TOKEN = ORIGIN + "/token";
    private static final String REVOKE = ORIGIN + "/revoke";
    private static final String MCP_URL = "https://mcp.example/mcp";
    private static final String LIVE_TOKEN = "live-access-token-0";
    private static final String LIVE_REFRESH = "live-refresh-token-0";

    private final ScriptedHttp http = new ScriptedHttp();
    private final AtomicInteger issued = new AtomicInteger();
    private boolean jwtTokens = true;
    private boolean honoursResource = true;
    private boolean refusesForeignResource;
    private boolean acceptsForeignAudience;
    private boolean rotatesRefreshTokens;
    private String metadataIssuer = ORIGIN;
    private OAuthAuthCodeStrategy strategy;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        strategy = TestOAuthStrategies.authenticated(new TestOAuthStrategies.Login(URI.create(ORIGIN),
                URI.create(MCP_URL), List.of("mcp:tools"), new TestOAuthStrategies.Client("client-1", null, "none",
                RegistrationMode.DCR), LIVE_TOKEN, LIVE_REFRESH, Instant.now().plusSeconds(3600), Clock.systemUTC()),
                TestOAuthStrategies.refusingRefresh());
        http.on("POST", TOKEN, this::refresh)
                .on("POST", REVOKE, ScriptedHttp.status(200))
                .on("POST", MCP_URL, this::mcp);
    }

    @Test
    void reportsAJwtIssuedForAnotherResourceThatTheServerAcceptsAsHighCertain() {
        acceptsForeignAudience = true;

        assertThat(audit()).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(TokenAudienceIssues.CONFIRMED);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.CERTAIN);
            assertThat(issue.detail()).contains("audience-probe-").contains(".invalid/mcp");
        });
    }

    @Test
    void staysSilentWhenTheServerRefusesTheForeignToken() {
        assertThat(audit()).isEmpty();
    }

    @Test
    void reportsAnAcceptedOpaqueTokenOnlyAsTentativeInformation() {
        jwtTokens = false;
        acceptsForeignAudience = true;

        assertThat(audit()).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(TokenAudienceIssues.UNCONFIRMED);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        });
    }

    @Test
    void staysSilentWhenTheAuthorizationServerIgnoresTheResourceParameter() {
        honoursResource = false;
        acceptsForeignAudience = true;

        assertThat(audit()).isEmpty();
    }

    @Test
    void staysSilentWhenTheAuthorizationServerRefusesATokenForAnotherResource() {
        refusesForeignResource = true;
        acceptsForeignAudience = true;

        assertThat(audit()).isEmpty();
        assertThat(liveToken()).isEqualTo(LIVE_TOKEN);
    }

    @Test
    void leavesTheLiveSessionWithATokenForThisServerAndTheRotatedRefreshToken() {
        rotatesRefreshTokens = true;
        acceptsForeignAudience = true;

        audit();

        assertThat(audienceOf(liveToken())).isEqualTo(MCP_URL);
        List<String> refreshes = bodiesTo(TOKEN);
        assertThat(refreshes).hasSize(2);
        assertThat(refreshes.get(1)).as("the restore uses the rotated refresh token")
                .contains("refresh_token=rotated-refresh-1").contains("resource=" + MCP_URL.replace(":", "%3A")
                        .replace("/", "%2F"));
    }

    @Test
    void revokesTheProbeTokenButNotTheSessionsRefreshToken() {
        acceptsForeignAudience = true;

        audit();

        assertThat(bodiesTo(REVOKE)).singleElement().satisfies(body -> {
            assertThat(body).contains("token_type_hint=access_token");
            assertThat(body).doesNotContain(LIVE_REFRESH);
        });
    }

    @Test
    void redactsEveryTokenInTheEvidence() {
        acceptsForeignAudience = true;

        assertThat(audit()).singleElement().satisfies(issue -> assertThat(issue.requestResponses())
                .allSatisfy(exchange -> {
                    String request = exchange.request().headers().toString() + exchange.request().bodyToString();
                    assertThat(request).doesNotContain(LIVE_REFRESH).doesNotContain("eyJ");
                }));
    }

    @Test
    void neverSendsTheRefreshTokenWhenTheMetadataNamesAnotherIssuer() {
        metadataIssuer = "https://evil.example";
        acceptsForeignAudience = true;

        assertThat(audit()).isEmpty();
        assertThat(http.sentTo(TOKEN)).isEmpty();
    }

    @Test
    void appliesOnlyWhileTheSessionHoldsARefreshToken() {
        assertThat(new TokenAudienceCheck(() -> strategy, McpEventLog.noop()).appliesTo(base())).isTrue();
        assertThat(new TokenAudienceCheck(() -> new BearerTokenAuthStrategy("static"), McpEventLog.noop())
                .appliesTo(base())).isFalse();
    }

    private List<AuditIssue> audit() {
        http.on("GET", ORIGIN + "/.well-known/oauth-authorization-server", json(200, "{\"issuer\":\"" + metadataIssuer
                + "\",\"token_endpoint\":\"" + TOKEN + "\",\"revocation_endpoint\":\"" + REVOKE + "\"}"));
        return new TokenAudienceCheck(() -> strategy, McpEventLog.noop()).audit(base(), http.http());
    }

    private String refresh(HttpRequest request) {
        Map<String, String> form = form(request.bodyToString());
        String resource = form.getOrDefault("resource", MCP_URL);
        if (refusesForeignResource && !resource.equals(MCP_URL)) {
            return json(400, "{\"error\":\"invalid_target\"}");
        }
        String audience = honoursResource ? resource : MCP_URL;
        int n = issued.incrementAndGet();
        String access = jwtTokens ? jwt(audience, n) : "opaque-" + (audience.equals(MCP_URL) ? "own" : "foreign") + "-" + n;
        String rotated = rotatesRefreshTokens ? ",\"refresh_token\":\"rotated-refresh-" + n + "\"" : "";
        return json(200, "{\"access_token\":\"" + access + "\",\"token_type\":\"Bearer\",\"expires_in\":3600" + rotated
                + "}");
    }

    private String mcp(HttpRequest request) {
        String authorization = request.headerValue("Authorization");
        String token = authorization == null ? "" : authorization.substring("Bearer ".length());
        boolean own = token.equals(LIVE_TOKEN) || token.startsWith("opaque-own")
                || (token.startsWith("eyJ") && MCP_URL.equals(audienceOf(token)));
        boolean foreign = token.startsWith("opaque-foreign") || (token.startsWith("eyJ") && !own);
        if (own || (foreign && acceptsForeignAudience)) {
            String id = request.bodyToString().replaceAll("(?s).*\"id\"\\s*:\\s*(\\d+).*", "$1");
            return json(200, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"tools\":[{\"name\":\"read_note\"}]}}");
        }
        return "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer\r\nContent-Type: application/json\r\n\r\n"
                + "{\"error\":\"invalid_token\"}";
    }

    private String liveToken() {
        return strategy.headers().get("Authorization").substring("Bearer ".length());
    }

    private List<String> bodiesTo(String url) {
        return http.sentTo(url).stream().map(HttpRequest::bodyToString).toList();
    }

    private static String jwt(String audience, int n) {
        return encode("{\"alg\":\"none\"}") + "." + encode("{\"aud\":\"" + audience + "\",\"jti\":\"" + n + "\"}") + ".sig";
    }

    private static String audienceOf(String jwt) {
        String payload = new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8);
        return payload.replaceAll(".*\"aud\":\"([^\"]*)\".*", "$1");
    }

    private static String encode(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static Map<String, String> form(String body) {
        return Arrays.stream(body.split("&")).map(pair -> pair.split("=", 2)).filter(pair -> pair.length == 2)
                .collect(Collectors.toMap(pair -> pair[0], pair -> URLDecoder.decode(pair[1], StandardCharsets.UTF_8),
                        (first, second) -> second));
    }

    private static HttpRequestResponse base() {
        HttpRequest request = HttpRequest.httpRequestFromUrl(MCP_URL).withMethod("POST")
                .withHeader("Content-Type", "application/json")
                .withHeader("Authorization", "Bearer " + LIVE_TOKEN)
                .withBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_note\"}}");
        return HttpRequestResponse.httpRequestResponse(request, HttpResponse.httpResponse(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}"));
    }
}
