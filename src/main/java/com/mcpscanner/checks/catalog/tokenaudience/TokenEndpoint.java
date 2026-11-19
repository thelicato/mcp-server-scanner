package com.mcpscanner.checks.catalog.tokenaudience;

import com.mcpscanner.checks.shared.oauth.AuthorizationServerMetadataFetcher;
import com.mcpscanner.checks.shared.oauth.OAuthHttp;

import java.net.URI;
import java.util.Optional;

/** The token and revocation endpoints of the session's own issuer, from metadata that names that issuer. */
record TokenEndpoint(URI token, Optional<URI> revocation) {

    static Optional<TokenEndpoint> of(OAuthHttp http, URI issuer) {
        return new AuthorizationServerMetadataFetcher(http).fetch(issuer, document -> document.webUri("issuer")
                .filter(declared -> sameIssuer(declared, issuer))
                .flatMap(ignored -> document.webUri("token_endpoint"))
                .map(token -> new TokenEndpoint(token, document.webUri("revocation_endpoint"))));
    }

    private static boolean sameIssuer(URI declared, URI issuer) {
        return strip(declared.toString()).equals(strip(issuer.toString()));
    }

    private static String strip(String uri) {
        return uri.endsWith("/") ? uri.substring(0, uri.length() - 1) : uri;
    }
}
