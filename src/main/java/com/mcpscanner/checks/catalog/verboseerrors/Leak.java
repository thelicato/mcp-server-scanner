package com.mcpscanner.checks.catalog.verboseerrors;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

record Leak(Malformation malformation, Map<Disclosure, List<String>> disclosures, HttpRequestResponse exchange) {

    Leak {
        disclosures = Collections.unmodifiableMap(new EnumMap<>(disclosures));
    }

    boolean disclosesBeyondVersions() {
        return disclosures.keySet().stream().anyMatch(disclosure -> disclosure != Disclosure.VERSION);
    }

    int strength() {
        return disclosures.containsKey(Disclosure.STACK_TRACE) ? 3 : disclosures.containsKey(Disclosure.SOURCE_PATH)
                ? 2 : 1;
    }
}
