package com.mcpscanner.checks.catalog.tokenaudience;

import com.mcpscanner.checks.shared.oauth.JsonDocument;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/** The aud claim of a JWT access token, read without verifying it; empty for an opaque token. */
record TokenAudience(List<String> audiences) {

    TokenAudience {
        audiences = List.copyOf(audiences);
    }

    static Optional<TokenAudience> of(String accessToken) {
        String[] parts = accessToken.split("\\.");
        if (parts.length != 3) {
            return Optional.empty();
        }
        try {
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            return JsonDocument.parse(payload).map(claims -> claims.text("aud").map(List::of)
                    .orElseGet(() -> claims.texts("aud"))).filter(audiences -> !audiences.isEmpty())
                    .map(TokenAudience::new);
        } catch (IllegalArgumentException notBase64) {
            return Optional.empty();
        }
    }

    boolean names(URI resource) {
        String expected = resource.toString();
        return audiences.stream().anyMatch(audience -> audience.equals(expected)
                || audience.equals(expected.endsWith("/") ? expected.substring(0, expected.length() - 1) : expected + "/"));
    }
}
