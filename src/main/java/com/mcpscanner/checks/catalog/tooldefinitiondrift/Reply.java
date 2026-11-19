package com.mcpscanner.checks.catalog.tooldefinitiondrift;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.MissingNode;
import com.mcpscanner.checks.shared.jsonrpc.McpReply;

import java.util.List;
import java.util.Optional;

record Reply(Optional<HttpRequestResponse> exchange, List<JsonNode> messages, boolean rateLimited) {

    static final String LIST_CHANGED = "notifications/tools/list_changed";

    Reply {
        messages = List.copyOf(messages);
    }

    boolean responded() {
        return messages.stream().anyMatch(McpReply::isResponse);
    }

    JsonNode result() {
        return messages.stream().filter(message -> message.has("result")).findFirst()
                .map(message -> message.get("result")).orElse(MissingNode.getInstance());
    }

    boolean announcesListChange() {
        return messages.stream().anyMatch(message -> !message.has("id")
                && LIST_CHANGED.equals(message.path("method").asText(null)));
    }
}
