package com.mcpscanner.checks.shared.differential;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.checks.shared.jsonrpc.McpReply;
import com.mcpscanner.mcp.TooManyRequests;

import java.util.Optional;

public final class ReplyText {

    private ReplyText() {
    }

    public static Optional<String> of(HttpRequestResponse exchange) {
        if (exchange == null || exchange.response() == null || TooManyRequests.answered(exchange)) {
            return Optional.empty();
        }
        return McpReply.answering(exchange, McpReply::isResponse).message().filter(JsonNode::isObject)
                .map(JsonNode::toString);
    }
}
