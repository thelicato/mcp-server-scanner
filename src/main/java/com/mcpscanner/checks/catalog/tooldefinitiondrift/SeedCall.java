package com.mcpscanner.checks.catalog.tooldefinitiondrift;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.checks.shared.jsonrpc.JsonRpcEnvelope;
import com.mcpscanner.mcp.McpMethods;
import com.mcpscanner.mcp.McpOperationFraming;

import java.util.Optional;

record SeedCall(String tool, ObjectNode params) {

    static Optional<SeedCall> of(HttpRequest request) {
        JsonRpcEnvelope envelope = JsonRpcEnvelope.of(request);
        if (!envelope.isJsonRpc2() || !envelope.hasScalarId()
                || envelope.method().filter(McpMethods.TOOLS_CALL::equals).isEmpty()) {
            return Optional.empty();
        }
        JsonNode params = envelope.root().orElseThrow().path("params");
        if (!(params instanceof ObjectNode object) || !params.path("name").isTextual()) {
            return Optional.empty();
        }
        return Optional.of(new SeedCall(params.path("name").asText(),
                McpOperationFraming.withoutProtocolEnvelope(object)));
    }
}
