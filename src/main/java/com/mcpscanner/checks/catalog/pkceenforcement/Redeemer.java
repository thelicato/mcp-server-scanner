package com.mcpscanner.checks.catalog.pkceenforcement;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.shared.oauth.AuthorizationParameters;
import com.mcpscanner.checks.shared.oauth.IssuedToken;
import com.mcpscanner.checks.shared.oauth.JsonDocument;
import com.mcpscanner.checks.shared.oauth.OAuthHttp;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

/** Exchanges authorization codes at the token endpoint and keeps every token it obtains for revocation. */
final class Redeemer {

    private static final String APPLICATION_JSON = "application/json";

    private final OAuthHttp http;
    private final URI tokenEndpoint;
    private final URI resource;
    private final List<IssuedToken> issued = new CopyOnWriteArrayList<>();

    Redeemer(OAuthHttp http, URI tokenEndpoint, URI resource) {
        this.http = http;
        this.tokenEndpoint = tokenEndpoint;
        this.resource = resource;
    }

    Redemption redeem(ProbeClient client, String code, Optional<String> verifier) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", code);
        form.put("redirect_uri", client.callback().toString());
        form.put("client_id", client.clientId());
        verifier.ifPresent(value -> form.put("code_verifier", value));
        form.put("resource", resource.toString());
        Optional<HttpRequestResponse> exchange = http.postForm(tokenEndpoint, AuthorizationParameters.encode(form),
                APPLICATION_JSON, Map.of());
        Optional<JsonDocument> tokens = exchange.flatMap(JsonDocument::fromSuccessfulResponse);
        Optional<String> access = tokens.flatMap(document -> document.text("access_token"));
        access.map(IssuedToken::access).ifPresent(issued::add);
        tokens.flatMap(document -> document.text("refresh_token")).map(IssuedToken::refresh).ifPresent(issued::add);
        return new Redemption(access, exchange);
    }

    List<IssuedToken> issued() {
        return List.copyOf(issued);
    }

    record Redemption(Optional<String> accessToken, Optional<HttpRequestResponse> exchange) {
    }
}
