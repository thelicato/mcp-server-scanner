package com.mcpscanner.testutil;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.scan.McpInsertionPointProvider;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public final class ToolArgumentServer {

    public static final String ENDPOINT = "http://mcp.example/mcp";

    private final String tool;
    private final JsonNode arguments;
    private final Function<JsonNode, Outcome> behaviour;
    private final List<JsonNode> received = Collections.synchronizedList(new ArrayList<>());

    public record Outcome(String text, boolean isError) {

        public static Outcome ok(String text) {
            return new Outcome(text, false);
        }

        public static Outcome error(String text) {
            return new Outcome(text, true);
        }
    }

    private ToolArgumentServer(String tool, JsonNode arguments, Function<JsonNode, Outcome> behaviour) {
        this.tool = tool;
        this.arguments = arguments;
        this.behaviour = behaviour;
    }

    public static ToolArgumentServer of(String tool, String argumentsJson, Function<JsonNode, Outcome> behaviour) {
        return new ToolArgumentServer(tool, parse(argumentsJson), behaviour);
    }

    public Http http() {
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> exchange(invocation.getArgument(0)));
        return http;
    }

    public HttpRequestResponse baseline() {
        HttpRequestResponse base = exchange(request());
        received.clear();
        return base;
    }

    public AuditInsertionPoint field(HttpRequestResponse base, String argumentPath) {
        return new McpInsertionPointProvider().provideInsertionPoints(base).stream()
                .filter(point -> point.name().endsWith("params.arguments." + argumentPath))
                .findFirst()
                .orElseThrow();
    }

    public List<JsonNode> received() {
        synchronized (received) {
            return List.copyOf(received);
        }
    }

    private HttpRequestResponse exchange(HttpRequest request) {
        JsonNode message = parse(request.bodyToString());
        JsonNode sent = message.path("params").path("arguments");
        received.add(sent);
        Outcome outcome = behaviour.apply(sent);
        ObjectNode envelope = McpObjectMapper.INSTANCE.createObjectNode().put("jsonrpc", "2.0");
        envelope.set("id", message.get("id"));
        ObjectNode result = envelope.putObject("result");
        result.putArray("content").addObject().put("type", "text").put("text", outcome.text());
        if (outcome.isError()) {
            result.put("isError", true);
        }
        return HttpRequestResponse.httpRequestResponse(request, HttpResponse.httpResponse(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + envelope));
    }

    private HttpRequest request() {
        ObjectNode envelope = McpObjectMapper.INSTANCE.createObjectNode().put("jsonrpc", "2.0").put("id", 7)
                .put("method", "tools/call");
        envelope.putObject("params").put("name", tool).set("arguments", arguments.deepCopy());
        return HttpRequest.httpRequestFromUrl(ENDPOINT).withMethod("POST")
                .withAddedHeader("Content-Type", "application/json").withBody(envelope.toString());
    }

    private static JsonNode parse(String json) {
        try {
            return McpObjectMapper.INSTANCE.readTree(json);
        } catch (Exception unparseable) {
            throw new IllegalStateException(unparseable);
        }
    }
}
