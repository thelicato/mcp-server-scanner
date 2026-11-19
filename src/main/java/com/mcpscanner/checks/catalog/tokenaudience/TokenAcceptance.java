package com.mcpscanner.checks.catalog.tokenaudience;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.checks.shared.auth.CredentialSubstitution;
import com.mcpscanner.checks.shared.auth.ToolsListProbe;
import com.mcpscanner.checks.shared.auth.oracle.BaselineEquivalenceOracle;
import com.mcpscanner.checks.shared.auth.oracle.OracleEvidence;
import com.mcpscanner.checks.shared.auth.oracle.OracleVerdict;

import java.util.List;
import java.util.function.Supplier;

/** Whether the MCP server answers tools/list for a token as it does for the user's own, while refusing controls. */
final class TokenAcceptance {

    static final String MALFORMED_TOKEN = "mcp-scanner-invalid-token";

    private final Http http;
    private final HttpRequest seed;
    private final CredentialSubstitution credentials;
    private final Supplier<AuthStrategy> authStrategy;
    private final BaselineEquivalenceOracle oracle = BaselineEquivalenceOracle.defaultOracle();
    private final ToolsListProbe toolsList = new ToolsListProbe(9_300);
    private HttpRequestResponse baseline;
    private List<HttpRequestResponse> refusedControls;

    TokenAcceptance(Http http, HttpRequest seed, Supplier<AuthStrategy> authStrategy) {
        this.http = http;
        this.seed = seed;
        this.authStrategy = authStrategy;
        this.credentials = new CredentialSubstitution(authStrategy);
    }

    void prime() {
        baseline = send(credentials.withIdentity(seed, authStrategy.get().headers()));
        refusedControls = List.of(send(credentials.anonymous(seed)), send(credentials.bearer(seed, MALFORMED_TOKEN)));
    }

    Judged judge(String accessToken) {
        HttpRequestResponse candidate = send(credentials.bearer(seed, accessToken));
        return new Judged(oracle.judge(new OracleEvidence(baseline, refusedControls, candidate)), candidate);
    }

    private HttpRequestResponse send(HttpRequest request) {
        return http.sendRequest(toolsList.on(request));
    }

    record Judged(OracleVerdict verdict, HttpRequestResponse exchange) {
    }
}
