package com.mcpscanner.checks.catalog.pkceenforcement;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.shared.oauth.JsonDocument;
import com.mcpscanner.checks.shared.oauth.OAuthHttp;
import com.mcpscanner.checks.shared.oauth.WellKnownLocations;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** The PKCE methods an authorization server advertises, and the metadata exchange that says so. */
record PkceMetadata(List<String> methods, HttpRequestResponse exchange) {

    private static final String METHODS = "code_challenge_methods_supported";

    PkceMetadata {
        methods = List.copyOf(methods);
    }

    static Optional<PkceMetadata> read(OAuthHttp http, URI issuer) {
        for (URI location : WellKnownLocations.authorizationServerMetadata(issuer)) {
            Optional<HttpRequestResponse> exchange = http.getJson(location);
            Optional<JsonDocument> document = exchange.flatMap(JsonDocument::fromSuccessfulResponse);
            if (document.isPresent()) {
                return Optional.of(new PkceMetadata(document.get().texts(METHODS), exchange.get()));
            }
        }
        return Optional.empty();
    }

    boolean advertises(String method) {
        return methods.contains(method);
    }

    List<String> problems() {
        List<String> problems = new ArrayList<>();
        if (methods.isEmpty()) {
            problems.add(METHODS + " is missing, so a client that follows the MCP specification refuses to "
                    + "proceed, and a client that does not may skip PKCE");
        } else if (!advertises("S256")) {
            problems.add(METHODS + " lists " + methods + " without S256");
        }
        if (advertises("plain")) {
            problems.add(METHODS + " lists plain, which does not protect a code whose authorization request was "
                    + "seen");
        }
        return problems;
    }
}
