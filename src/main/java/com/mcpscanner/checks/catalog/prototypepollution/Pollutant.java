package com.mcpscanner.checks.catalog.prototypepollution;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.checks.shared.random.RandomHex;

record Pollutant(String property, String value) {

    static Pollutant random() {
        return new Pollutant("mcppp" + RandomHex.of(4), "mcpppvalue" + RandomHex.of(6));
    }

    JsonNode object() {
        ObjectNode object = JsonNodeFactory.instance.objectNode();
        object.put(property, value);
        return object;
    }
}
