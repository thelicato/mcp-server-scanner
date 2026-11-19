package com.mcpscanner.checks.shared.differential;

import burp.api.montoya.http.message.requests.HttpRequest;

public record SplicedRequest(HttpRequest request, String splicedText) {
}
