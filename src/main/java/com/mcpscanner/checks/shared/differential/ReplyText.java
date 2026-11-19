package com.mcpscanner.checks.shared.differential;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.checks.shared.jsonrpc.McpReply;
import com.mcpscanner.mcp.TooManyRequests;

import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

public final class ReplyText {

    public static final String REFLECTED = "[reflected]";
    private static final int SHORTEST_MASKED = 2;
    private static final List<String> ENVELOPE_MEMBERS = List.of("id", "jsonrpc");

    private ReplyText() {
    }

    public static Optional<String> of(HttpRequestResponse exchange) {
        return reply(exchange).map(JsonNode::toString);
    }

    public static Optional<String> canonical(HttpRequestResponse exchange, Collection<String> reflections) {
        List<String> masked = reflections.stream().filter(text -> text != null && text.length() >= SHORTEST_MASKED)
                .distinct().sorted(Comparator.comparingInt(String::length).reversed()).toList();
        return reply(exchange).map(message -> {
            ObjectNode copy = message.deepCopy();
            copy.remove(ENVELOPE_MEMBERS);
            return exchange.response().statusCode() + " " + masked(copy, masked);
        });
    }

    private static Optional<JsonNode> reply(HttpRequestResponse exchange) {
        if (exchange == null || exchange.response() == null || TooManyRequests.answered(exchange)) {
            return Optional.empty();
        }
        return McpReply.answering(exchange, McpReply::isResponse).message().filter(JsonNode::isObject);
    }

    private static JsonNode masked(JsonNode node, List<String> reflections) {
        if (node.isTextual()) {
            String text = node.textValue();
            for (String reflection : reflections) {
                text = text.replace(reflection, REFLECTED);
            }
            return JsonNodeFactory.instance.textNode(text);
        }
        if (node.isObject()) {
            ObjectNode copy = JsonNodeFactory.instance.objectNode();
            node.properties().forEach(member -> copy.set(member.getKey(), masked(member.getValue(), reflections)));
            return copy;
        }
        if (node.isArray()) {
            ArrayNode copy = JsonNodeFactory.instance.arrayNode();
            node.forEach(element -> copy.add(masked(element, reflections)));
            return copy;
        }
        return node;
    }
}
