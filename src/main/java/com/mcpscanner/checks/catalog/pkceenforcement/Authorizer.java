package com.mcpscanner.checks.catalog.pkceenforcement;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.shared.oauth.AuthorizationParameters;
import com.mcpscanner.checks.shared.oauth.AuthorizationServer;
import com.mcpscanner.checks.shared.oauth.CallbackResponse;
import com.mcpscanner.checks.shared.oauth.OAuthHttp;
import com.mcpscanner.checks.shared.oauth.Pkce;
import com.mcpscanner.checks.shared.oauth.ProbeCallback;
import com.mcpscanner.checks.shared.oauth.RedirectTrail;
import com.mcpscanner.checks.shared.oauth.SameOriginRedirects;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/** Requests an authorization code with no user session, carrying the PKCE parameters of one challenge. */
final class Authorizer {

    static final int MAX_REDIRECTS = 5;

    private final SameOriginRedirects redirects;
    private final AuthorizationServer server;

    Authorizer(OAuthHttp http, AuthorizationServer server) {
        this.redirects = SameOriginRedirects.carryingCookies(http, MAX_REDIRECTS);
        this.server = server;
    }

    Attempt authorize(ProbeClient client, Challenge challenge) {
        Pkce pkce = Pkce.generate();
        String state = UUID.randomUUID().toString();
        Map<String, String> parameters = AuthorizationParameters.of(server, "code", client.clientId(),
                client.callback(), state, pkce);
        challenge.applyTo(parameters, pkce);
        URI request = AuthorizationParameters.withQuery(server.authorizationEndpoint(), parameters);
        return redirects.follow(request, client::isCallback)
                .map(trail -> attempt(trail, client, state, pkce, challenge))
                .orElseGet(() -> new Attempt(challenge, pkce, Optional.empty(), false, List.of(), false));
    }

    private static Attempt attempt(RedirectTrail trail, ProbeClient client, String state, Pkce pkce,
                                   Challenge challenge) {
        Optional<CallbackResponse> callback = trail.stoppedAt()
                .flatMap(location -> ProbeCallback.response(client.callback(), location, state));
        return new Attempt(challenge, pkce, callback.flatMap(CallbackResponse::code), callback.isPresent(),
                trail.exchanges(), trail.hopLimitReached());
    }

    record Attempt(Challenge challenge, Pkce pkce, Optional<String> code, boolean reachedCallback,
                   List<HttpRequestResponse> exchanges, boolean hopLimitReached) {

        Attempt {
            exchanges = List.copyOf(exchanges);
        }
    }
}
