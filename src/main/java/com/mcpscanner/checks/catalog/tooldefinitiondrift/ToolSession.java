package com.mcpscanner.checks.catalog.tooldefinitiondrift;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.shared.jsonrpc.JsonNodes;
import com.mcpscanner.checks.shared.jsonrpc.JsonRpcMessages;
import com.mcpscanner.checks.shared.session.ProbeSessions;
import com.mcpscanner.core.connection.HttpProbeSession;
import com.mcpscanner.core.protocol.McpFlow;
import com.mcpscanner.core.protocol.McpRequests;
import com.mcpscanner.mcp.McpMethods;
import com.mcpscanner.mcp.McpOperationFraming;
import com.mcpscanner.mcp.TooManyRequests;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

final class ToolSession implements AutoCloseable {

    static final int MAX_PAGES = 20;

    private final HttpProbeSession session;
    private final AtomicReference<HttpRequestResponse> lastExchange;
    private final CheckLog log;
    private long nextId = 1;

    private ToolSession(HttpProbeSession session, AtomicReference<HttpRequestResponse> lastExchange, CheckLog log) {
        this.session = session;
        this.lastExchange = lastExchange;
        this.log = log;
    }

    static Opening open(ProbeSessions sessions, HttpRequestResponse base, Http http, CheckLog log) {
        AtomicReference<HttpRequestResponse> lastExchange = new AtomicReference<>();
        try {
            return new Opening(sessions.openHttp(base, http, lastExchange::set)
                    .map(session -> new ToolSession(session, lastExchange, log)), false);
        } catch (RuntimeException refused) {
            log.info("probe session refused: " + describe(refused));
            return new Opening(Optional.empty(), TooManyRequests.answered(lastExchange.get()));
        }
    }

    static Listing listOnce(ProbeSessions sessions, HttpRequestResponse base, Http http, CheckLog log) {
        Opening opening = open(sessions, base, http, log);
        if (opening.session().isEmpty()) {
            return Listing.failed(opening.rateLimited(), List.of());
        }
        try (ToolSession session = opening.session().get()) {
            return session.list();
        }
    }

    record Opening(Optional<ToolSession> session, boolean rateLimited) {
    }

    Listing list() {
        Map<String, JsonNode> tools = new LinkedHashMap<>();
        List<HttpRequestResponse> exchanges = new ArrayList<>();
        Set<String> cursors = new HashSet<>();
        boolean announced = false;
        String cursor = null;
        for (int page = 0; page < MAX_PAGES; page++) {
            Reply reply = send(session.session().request(McpMethods.TOOLS_LIST, cursor, nextId++));
            reply.exchange().ifPresent(exchanges::add);
            if (!reply.result().isObject()) {
                return Listing.failed(reply.rateLimited(), exchanges);
            }
            announced |= reply.announcesListChange();
            JsonNodes.elements(reply.result().path("tools")).stream()
                    .filter(tool -> tool.path("name").isTextual())
                    .forEach(tool -> tools.putIfAbsent(tool.path("name").asText(), tool));
            JsonNode next = reply.result().path("nextCursor");
            if (!next.isTextual() || !cursors.add(next.asText())) {
                break;
            }
            cursor = next.asText();
        }
        return Listing.of(new ToolSnapshot(tools), announced, exchanges);
    }

    Reply call(ObjectNode params) {
        return send(McpOperationFraming.operation(McpMethods.TOOLS_CALL, params, nextId++, framer()));
    }

    @Override
    public void close() {
        try {
            session.close();
        } catch (RuntimeException failedTermination) {
            log.info("probe session DELETE failed: " + describe(failedTermination));
        }
    }

    private Reply send(McpRequests.Request request) {
        lastExchange.set(null);
        McpFlow.HttpResponse response = null;
        try {
            response = session.send(request);
        } catch (RuntimeException unanswered) {
            log.info("probe request unanswered: " + describe(unanswered));
        }
        Optional<HttpRequestResponse> exchange = Optional.ofNullable(lastExchange.get());
        List<JsonNode> messages = response == null || !response.successful()
                ? List.of() : JsonRpcMessages.in(response.body());
        return new Reply(exchange, messages, exchange.filter(TooManyRequests::answered).isPresent());
    }

    private McpOperationFraming.Framer framer() {
        McpFlow.Session framing = session.session();
        return new McpOperationFraming.Framer() {
            @Override
            public McpRequests.Request operation(String method, String paramsJson, long id) {
                return framing.operation(method, paramsJson, id);
            }

            @Override
            public McpRequests.Request notification(String method, String paramsJson) {
                return framing.notification(method, paramsJson);
            }
        };
    }

    private static String describe(RuntimeException failure) {
        return failure.getClass().getSimpleName() + ": " + failure.getMessage();
    }
}
