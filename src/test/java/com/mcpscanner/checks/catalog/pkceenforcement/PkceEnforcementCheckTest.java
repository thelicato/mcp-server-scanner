package com.mcpscanner.checks.catalog.pkceenforcement;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.shared.oauth.ScriptedHttp;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.mcpscanner.checks.catalog.pkceenforcement.PkceServer.ACCESS_TOKEN_PREFIX;
import static com.mcpscanner.checks.catalog.pkceenforcement.PkceServer.AUTHORIZE;
import static com.mcpscanner.checks.catalog.pkceenforcement.PkceServer.CLIENT_URI;
import static com.mcpscanner.checks.catalog.pkceenforcement.PkceServer.MCP;
import static com.mcpscanner.checks.catalog.pkceenforcement.PkceServer.REVOKE;
import static org.assertj.core.api.Assertions.assertThat;

class PkceEnforcementCheckTest {

    private static final String NOT_REQUIRED = "MCP OAuth authorization code issued without PKCE";
    private static final String NOT_CHECKED = "MCP OAuth PKCE code_verifier not checked";
    private static final String PLAIN = "MCP OAuth plain PKCE method accepted";
    private static final String METADATA = "MCP OAuth PKCE support not advertised as required";

    private final PkceEnforcementCheck check = new PkceEnforcementCheck(McpEventLog.noop());
    private PkceServer server;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        server = new PkceServer();
    }

    @Test
    void reportsNothingForAServerThatEnforcesS256() {
        assertThat(audit()).isEmpty();
        assertThat(server.http().sentTo(AUTHORIZE)).hasSize(3);
        assertThat(server.http().sentTo(CLIENT_URI)).as("the probe client is deleted").hasSize(1);
    }

    @Test
    void reportsACodeIssuedAndRedeemedWithoutAChallengeAsMediumCertain() {
        server.challengeOptional();

        assertThat(audit()).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(NOT_REQUIRED);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.CERTAIN);
            assertThat(issue.detail()).contains("no code_challenge").contains("with no code_verifier");
        });
        assertThat(server.sentTo(REVOKE)).as("the token is revoked").singleElement()
                .satisfies(body -> assertThat(body).contains(ACCESS_TOKEN_PREFIX));
    }

    @Test
    void reportsAWrongVerifierThatStillRedeems() {
        server.verifierUnchecked();

        assertThat(audit()).extracting(AuditIssue::name).containsExactly(NOT_CHECKED);
    }

    @Test
    void reportsPlainAcceptedWhenOnlyS256IsAdvertised() {
        server.plainAccepted();

        assertThat(audit()).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(PLAIN);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
        });
    }

    @Test
    void reportsMissingMethodsMetadataAsInformationEvenWhenALoginStopsTheCodeTests() {
        server.advertising(null).loginRequired();

        assertThat(audit()).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(METADATA);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
            assertThat(issue.detail()).contains("code_challenge_methods_supported is missing");
        });
        assertThat(server.http().sentTo(AUTHORIZE)).as("no further code requests after a login page").hasSize(1);
    }

    @Test
    void reportsAdvertisedPlainAndSkipsThePlainCodeTest() {
        server.advertising("[\"S256\",\"plain\"]");

        assertThat(audit()).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(METADATA);
            assertThat(issue.detail()).contains("lists plain");
        });
        assertThat(server.http().sentTo(AUTHORIZE)).hasSize(2);
    }

    @Test
    void redactsIssuedTokensInTheEvidence() {
        server.challengeOptional();

        assertThat(audit()).singleElement().satisfies(issue -> assertThat(issue.requestResponses())
                .allSatisfy(exchange -> assertThat(exchange.response() == null ? ""
                        : exchange.response().bodyToString()).doesNotContain(ACCESS_TOKEN_PREFIX)));
    }

    @Test
    void doesNothingWithoutAnAuthorizationServer() {
        ScriptedHttp nothing = new ScriptedHttp();

        assertThat(check.audit(base(), nothing.http())).isEmpty();
        assertThat(nothing.sentUrls()).noneMatch(url -> url.contains("/authorize") || url.contains("/register"));
    }

    private List<AuditIssue> audit() {
        return check.audit(base(), server.http().http());
    }

    private static HttpRequestResponse base() {
        HttpRequest request = HttpRequest.httpRequestFromUrl(MCP).withMethod("POST")
                .withBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}")
                .withAddedHeader("Content-Type", "application/json")
                .withAddedHeader("Authorization", "Bearer scanner-token");
        return HttpRequestResponse.httpRequestResponse(request, null);
    }
}
