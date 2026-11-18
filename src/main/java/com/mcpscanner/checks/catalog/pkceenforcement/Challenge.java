package com.mcpscanner.checks.catalog.pkceenforcement;

import com.mcpscanner.checks.shared.oauth.Pkce;

import java.util.Map;

/** The PKCE parameters an authorization request carries. */
enum Challenge {

    NONE("no code_challenge"),
    S256("an S256 code_challenge"),
    PLAIN("a plain code_challenge");

    private final String description;

    Challenge(String description) {
        this.description = description;
    }

    String description() {
        return description;
    }

    void applyTo(Map<String, String> parameters, Pkce pkce) {
        switch (this) {
            case NONE -> {
                parameters.remove("code_challenge");
                parameters.remove("code_challenge_method");
            }
            case S256 -> {
                parameters.put("code_challenge_method", "S256");
                parameters.put("code_challenge", pkce.challenge());
            }
            case PLAIN -> {
                parameters.put("code_challenge_method", "plain");
                parameters.put("code_challenge", pkce.verifier());
            }
        }
    }
}
