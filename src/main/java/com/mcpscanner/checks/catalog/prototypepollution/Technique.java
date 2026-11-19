package com.mcpscanner.checks.catalog.prototypepollution;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

enum Technique {
    PROTO_KEY("__proto__") {
        @Override
        JsonNode carrying(Pollutant pollutant) {
            return pollutant.object();
        }
    },
    CONSTRUCTOR_PROTOTYPE("constructor") {
        @Override
        JsonNode carrying(Pollutant pollutant) {
            ObjectNode constructor = JsonNodeFactory.instance.objectNode();
            constructor.set("prototype", pollutant.object());
            return constructor;
        }
    };

    private final String key;

    Technique(String key) {
        this.key = key;
    }

    abstract JsonNode carrying(Pollutant pollutant);

    String key() {
        return key;
    }

    String described(Pollutant pollutant) {
        return "\"" + key + "\": " + carrying(pollutant);
    }
}
