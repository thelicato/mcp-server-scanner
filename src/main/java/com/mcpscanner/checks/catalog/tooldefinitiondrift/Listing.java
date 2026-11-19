package com.mcpscanner.checks.catalog.tooldefinitiondrift;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;
import java.util.Map;
import java.util.Optional;

record Listing(Optional<ToolSnapshot> snapshot, boolean announcesListChange, boolean rateLimited,
               List<HttpRequestResponse> exchanges) {

    Listing {
        exchanges = List.copyOf(exchanges);
    }

    static Listing of(ToolSnapshot snapshot, boolean announcesListChange, List<HttpRequestResponse> exchanges) {
        return new Listing(Optional.of(snapshot), announcesListChange, false, exchanges);
    }

    static Listing failed(boolean rateLimited, List<HttpRequestResponse> exchanges) {
        return new Listing(Optional.empty(), false, rateLimited, exchanges);
    }

    boolean failed() {
        return snapshot.isEmpty();
    }

    ToolSnapshot tools() {
        return snapshot.orElseGet(() -> new ToolSnapshot(Map.of()));
    }

    Optional<HttpRequestResponse> firstExchange() {
        return exchanges.stream().findFirst();
    }
}
