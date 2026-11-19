package com.mcpscanner.checks.catalog.nosqlinjection;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.shared.differential.FieldProbe;
import com.mcpscanner.checks.shared.differential.ReplyText;

import java.util.Objects;
import java.util.Optional;

record Probe(HttpRequestResponse exchange, Optional<String> shape) {

    static Probe sent(FieldProbe field, Payload payload) {
        HttpRequestResponse exchange = payload.send(field);
        return new Probe(exchange, ReplyText.canonical(exchange, payload.reflections()));
    }

    boolean matches(Probe other) {
        return shape.isPresent() && Objects.equals(shape, other.shape);
    }

    boolean differsFrom(Probe other) {
        return shape.isPresent() && other.shape.isPresent() && !matches(other);
    }
}
