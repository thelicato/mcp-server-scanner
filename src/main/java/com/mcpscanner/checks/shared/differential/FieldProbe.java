package com.mcpscanner.checks.shared.differential;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.checks.shared.evidence.PayloadHighlights;
import com.mcpscanner.http.TextMarkers;
import com.mcpscanner.mcp.TooManyRequests;

import java.util.List;
import java.util.Optional;

public final class FieldProbe {

    public static final int UNANSWERED_PROBES_BEFORE_GIVING_UP = 2;

    private final HttpRequestResponse base;
    private final AuditInsertionPoint insertionPoint;
    private final Http http;
    private final String described;
    private Optional<JsonSplice> splice;
    private int consecutiveUnanswered;
    private boolean rateLimited;

    public FieldProbe(HttpRequestResponse base, AuditInsertionPoint insertionPoint, Http http, String described) {
        this.base = base;
        this.insertionPoint = insertionPoint;
        this.http = http;
        this.described = described;
    }

    public String described() {
        return described;
    }

    public String original() {
        String value = insertionPoint.baseValue();
        return value == null ? "" : value;
    }

    public HttpRequest baseRequest() {
        return base.request();
    }

    public HttpRequestResponse baseline() {
        return base.response() != null ? base : sent(base.request());
    }

    public HttpRequestResponse resendBaseline() {
        return gaveUp() ? null : sent(base.request());
    }

    public HttpRequestResponse send(String payload) {
        if (gaveUp()) {
            return null;
        }
        HttpRequestResponse exchange = sent(insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(payload)));
        return PayloadHighlights.ofPayload(exchange, insertionPoint, payload);
    }

    public HttpRequestResponse send(SplicedRequest spliced) {
        if (gaveUp()) {
            return null;
        }
        HttpRequestResponse exchange = sent(spliced.request());
        return exchange == null ? null : TextMarkers.inRequest(exchange, List.of(spliced.splicedText()));
    }

    public Optional<JsonSplice> splice() {
        if (splice == null) {
            splice = JsonSplice.of(insertionPoint, base.request());
        }
        return splice;
    }

    public boolean gaveUp() {
        return consecutiveUnanswered >= UNANSWERED_PROBES_BEFORE_GIVING_UP;
    }

    public boolean unresponsive() {
        return !rateLimited && gaveUp();
    }

    private HttpRequestResponse sent(HttpRequest request) {
        HttpRequestResponse exchange = http.sendRequest(request);
        consecutiveUnanswered = exchange == null || exchange.response() == null ? consecutiveUnanswered + 1 : 0;
        rateLimited |= TooManyRequests.answered(exchange);
        return exchange;
    }
}
