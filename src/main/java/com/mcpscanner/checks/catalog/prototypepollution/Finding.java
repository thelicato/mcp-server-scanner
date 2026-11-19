package com.mcpscanner.checks.catalog.prototypepollution;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;
import java.util.Objects;

record Finding(Technique technique, Pollutant first, List<HttpRequestResponse> evidence) {

    Finding {
        evidence = evidence.stream().filter(Objects::nonNull).toList();
    }
}
