package com.mcpscanner.checks.catalog.tokenaudience;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.auth.grant.IssuedTokens;
import com.mcpscanner.auth.grant.RefreshGrant;
import com.mcpscanner.checks.shared.oauth.AuthorizationParameters;
import com.mcpscanner.checks.shared.oauth.JsonDocument;
import com.mcpscanner.checks.shared.oauth.OAuthHttp;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/** Refreshes the live grant at the token endpoint, authenticating as the grant's own client. */
final class Refresher {

    private static final Duration DEFAULT_LIFETIME = Duration.ofMinutes(5);

    private final OAuthHttp http;
    private final URI tokenEndpoint;

    Refresher(OAuthHttp http, URI tokenEndpoint) {
        this.http = http;
        this.tokenEndpoint = tokenEndpoint;
    }

    Refresh refresh(RefreshGrant grant, Optional<URI> resource) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "refresh_token");
        form.put("refresh_token", grant.refreshToken());
        resource.ifPresent(uri -> form.put("resource", uri.toString()));
        Map<String, String> headers = new LinkedHashMap<>();
        Optional<String> secret = grant.client().type().isConfidential() ? grant.client().secret() : Optional.empty();
        secret.ifPresentOrElse(value -> headers.put("Authorization", basic(grant.client().clientId(), value)),
                () -> form.put("client_id", grant.client().clientId()));
        Optional<HttpRequestResponse> exchange = http.postForm(tokenEndpoint, AuthorizationParameters.encode(form),
                "application/json", headers);
        return new Refresh(exchange, exchange.flatMap(JsonDocument::fromSuccessfulResponse).flatMap(Refresher::tokens));
    }

    private static Optional<IssuedTokens> tokens(JsonDocument body) {
        return body.text("access_token").map(access -> new IssuedTokens(access, body.text("refresh_token"),
                DEFAULT_LIFETIME));
    }

    private static String basic(String clientId, String secret) {
        String pair = URLEncoder.encode(clientId, StandardCharsets.UTF_8) + ":"
                + URLEncoder.encode(secret, StandardCharsets.UTF_8);
        return "Basic " + Base64.getEncoder().encodeToString(pair.getBytes(StandardCharsets.UTF_8));
    }

    record Refresh(Optional<HttpRequestResponse> exchange, Optional<IssuedTokens> tokens) {
    }
}
