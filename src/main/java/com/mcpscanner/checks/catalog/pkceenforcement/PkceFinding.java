package com.mcpscanner.checks.catalog.pkceenforcement;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.net.URI;
import java.util.List;

record PkceFinding(FindingKind kind, URI location, List<String> facts, List<HttpRequestResponse> evidence) {

    PkceFinding {
        facts = List.copyOf(facts);
        evidence = List.copyOf(evidence);
    }
}
