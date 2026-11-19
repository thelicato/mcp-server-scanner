package com.mcpscanner.checks.catalog.nosqlinjection;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.checks.shared.differential.FieldProbe;
import com.mcpscanner.checks.shared.jsonrpc.JsonNodes;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

sealed interface Payload {

    HttpRequestResponse send(FieldProbe field);

    List<String> reflections();

    String described();

    record Text(String value) implements Payload {

        @Override
        public HttpRequestResponse send(FieldProbe field) {
            return field.send(value);
        }

        @Override
        public List<String> reflections() {
            return List.of(value);
        }

        @Override
        public String described() {
            return value;
        }
    }

    record Value(JsonNode value) implements Payload {

        @Override
        public HttpRequestResponse send(FieldProbe field) {
            return field.splice().map(splice -> field.send(splice.withValue(value))).orElse(null);
        }

        @Override
        public List<String> reflections() {
            List<String> forms = new ArrayList<>(List.of(value.toString(), spaced(value, '"'), spaced(value, '\'')));
            JsonNodes.fields(value).stream().map(Map.Entry::getValue).filter(JsonNode::isTextual)
                    .map(JsonNode::textValue).forEach(forms::add);
            return forms;
        }

        @Override
        public String described() {
            return value.toString();
        }

        private static String spaced(JsonNode object, char quote) {
            List<String> members = JsonNodes.fields(object).stream().map(member -> quote + member.getKey() + quote
                    + ": " + quote + member.getValue().asText() + quote).toList();
            return "{" + String.join(", ", members) + "}";
        }
    }
}
