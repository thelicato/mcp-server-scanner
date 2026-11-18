package com.mcpscanner.checks.catalog.tokenpassthrough;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.shared.redaction.ExchangeRedactor;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** The credential values the scanning user sends, and where they turn up in a request the server made. */
final class ClientCredentials {

    static final int MINIMUM_LENGTH = 8;

    private final Set<String> secrets;

    private ClientCredentials(Set<String> secrets) {
        this.secrets = Set.copyOf(secrets);
    }

    static ClientCredentials of(Map<String, String> credentialHeaders) {
        Set<String> secrets = new LinkedHashSet<>();
        credentialHeaders.values().forEach(value -> addSecretsOf(value, secrets));
        secrets.removeIf(secret -> secret.length() < MINIMUM_LENGTH);
        return new ClientCredentials(secrets);
    }

    boolean isEmpty() {
        return secrets.isEmpty();
    }

    List<String> foundIn(HttpRequest request) {
        List<String> places = new ArrayList<>();
        for (HttpHeader header : request.headers()) {
            if (carries(header.value())) {
                places.add("the " + header.name() + " header");
            }
        }
        if (carries(request.path()) || carries(URLDecoder.decode(request.path(), StandardCharsets.UTF_8))) {
            places.add("the URL");
        }
        if (carries(request.bodyToString())) {
            places.add("the body");
        }
        return places;
    }

    ExchangeRedactor redactor() {
        return new ExchangeRedactor(secrets);
    }

    private boolean carries(String text) {
        return text != null && secrets.stream().anyMatch(text::contains);
    }

    private static void addSecretsOf(String value, Set<String> secrets) {
        if (value == null) {
            return;
        }
        String trimmed = value.trim();
        secrets.add(trimmed);
        int space = trimmed.indexOf(' ');
        if (space > 0) {
            secrets.add(trimmed.substring(space + 1).trim());
        }
        for (String cookie : trimmed.split(";")) {
            int equals = cookie.indexOf('=');
            if (equals > 0) {
                secrets.add(cookie.substring(equals + 1).trim());
            }
        }
    }
}
