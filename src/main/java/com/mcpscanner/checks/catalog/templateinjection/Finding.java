package com.mcpscanner.checks.catalog.templateinjection;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;
import java.util.Objects;

record Finding(TemplateSyntax syntax, Product first, List<HttpRequestResponse> evidence) {

    Finding {
        evidence = evidence.stream().filter(Objects::nonNull).toList();
    }
}
