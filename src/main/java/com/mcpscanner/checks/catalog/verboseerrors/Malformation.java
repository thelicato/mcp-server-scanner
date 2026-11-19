package com.mcpscanner.checks.catalog.verboseerrors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.mcp.McpMethods;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

enum Malformation {
    PARAMS_NOT_AN_OBJECT("params sent as a string instead of an object") {
        @Override
        Optional<ObjectNode> applyTo(ObjectNode message) {
            ObjectNode copy = message.deepCopy();
            copy.put("params", "mcp-scanner-malformed-params");
            return Optional.of(copy);
        }
    },
    TYPE_CONFUSION("every argument sent with another JSON type") {
        @Override
        Optional<ObjectNode> applyTo(ObjectNode message) {
            ObjectNode copy = message.deepCopy();
            ObjectNode target = target(copy).orElse(null);
            if (target == null || members(target).isEmpty()) {
                return Optional.empty();
            }
            members(target).forEach(member -> target.set(member.getKey(), confused(member.getValue())));
            return Optional.of(copy);
        }
    },
    OVERSIZED_VALUE("the first string argument sent as " + Malformation.OVERSIZED_LENGTH + " characters") {
        @Override
        Optional<ObjectNode> applyTo(ObjectNode message) {
            ObjectNode copy = message.deepCopy();
            return target(copy).flatMap(target -> members(target).stream()
                    .filter(member -> member.getValue().isTextual()).findFirst()
                    .map(member -> {
                        target.put(member.getKey(), "A".repeat(OVERSIZED_LENGTH));
                        return copy;
                    }));
        }
    },
    MISSING_ARGUMENTS("every argument left out") {
        @Override
        Optional<ObjectNode> applyTo(ObjectNode message) {
            ObjectNode copy = message.deepCopy();
            ObjectNode target = target(copy).orElse(null);
            if (target == null || members(target).isEmpty()) {
                return Optional.empty();
            }
            members(target).forEach(member -> target.remove(member.getKey()));
            return Optional.of(copy);
        }
    };

    static final int OVERSIZED_LENGTH = 65_536;

    private static final String META = "_meta";

    private final String described;

    Malformation(String described) {
        this.described = described;
    }

    abstract Optional<ObjectNode> applyTo(ObjectNode message);

    String described() {
        return described;
    }

    private static Optional<ObjectNode> target(ObjectNode message) {
        if (!(message.get("params") instanceof ObjectNode params)) {
            return Optional.empty();
        }
        String method = message.path("method").asText();
        boolean takesArguments = McpMethods.TOOLS_CALL.equals(method) || "prompts/get".equals(method);
        if (takesArguments && params.get("arguments") instanceof ObjectNode arguments && !arguments.isEmpty()) {
            return Optional.of(arguments);
        }
        return Optional.of(params);
    }

    private static List<Map.Entry<String, JsonNode>> members(ObjectNode target) {
        List<Map.Entry<String, JsonNode>> members = new ArrayList<>();
        target.properties().forEach(member -> {
            if (!META.equals(member.getKey())) {
                members.add(Map.entry(member.getKey(), member.getValue()));
            }
        });
        return members;
    }

    private static JsonNode confused(JsonNode value) {
        JsonNodeFactory nodes = JsonNodeFactory.instance;
        if (value.isTextual()) {
            return nodes.numberNode(-1.5e308);
        }
        if (value.isObject()) {
            return nodes.arrayNode().add("mcp-scanner-type-confusion");
        }
        if (value.isArray()) {
            return nodes.objectNode().put("mcp-scanner", "type-confusion");
        }
        return nodes.textNode("mcp-scanner-type-confusion");
    }
}
