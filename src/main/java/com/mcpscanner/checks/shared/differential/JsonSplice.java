package com.mcpscanner.checks.shared.differential;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.checks.shared.jsonrpc.JsonRpcMessages;
import com.mcpscanner.checks.shared.random.RandomHex;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class JsonSplice {

    private static final String MARKER_PREFIX = "mcpsplice";
    private static final int MARKER_BYTES = 8;

    private final HttpRequest marked;
    private final JsonNode root;
    private final List<Object> path;
    private final Optional<JsonNode> original;

    private JsonSplice(HttpRequest marked, JsonNode root, List<Object> path, Optional<JsonNode> original) {
        this.marked = marked;
        this.root = root;
        this.path = List.copyOf(path);
        this.original = original;
    }

    public static Optional<JsonSplice> of(AuditInsertionPoint insertionPoint, HttpRequest base) {
        String marker = MARKER_PREFIX + RandomHex.of(MARKER_BYTES);
        HttpRequest marked;
        try {
            marked = insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(marker));
        } catch (RuntimeException unbuildable) {
            return Optional.empty();
        }
        Optional<JsonNode> root = JsonRpcMessages.parsed(marked.bodyToString()).filter(JsonNode::isContainerNode);
        if (root.isEmpty()) {
            return Optional.empty();
        }
        List<List<Object>> found = new ArrayList<>();
        collect(root.get(), marker, new ArrayList<>(), found);
        if (found.size() != 1 || found.get(0).isEmpty()) {
            return Optional.empty();
        }
        Optional<JsonNode> original = JsonRpcMessages.parsed(base.bodyToString())
                .flatMap(baseRoot -> at(baseRoot, found.get(0)));
        return Optional.of(new JsonSplice(marked, root.get(), found.get(0), original));
    }

    public SplicedRequest withValue(JsonNode value) {
        JsonNode copy = root.deepCopy();
        put(parentIn(copy), last(), value);
        return spliced(copy, value.toString());
    }

    public boolean inObject() {
        return original.isPresent() && last() instanceof String && parentIn(root) instanceof ObjectNode;
    }

    public Optional<SplicedRequest> withSibling(String key, JsonNode value) {
        if (!inObject()) {
            return Optional.empty();
        }
        JsonNode copy = root.deepCopy();
        if (!(parentIn(copy) instanceof ObjectNode parent) || parent.has(key)) {
            return Optional.empty();
        }
        parent.set((String) last(), original.get().deepCopy());
        parent.set(key, value);
        ObjectNode shown = parent.objectNode();
        shown.set(key, value);
        String member = shown.toString();
        return Optional.of(spliced(copy, member.substring(1, member.length() - 1)));
    }

    private SplicedRequest spliced(JsonNode body, String splicedText) {
        return new SplicedRequest(marked.withBody(body.toString()), splicedText);
    }

    private JsonNode parentIn(JsonNode copy) {
        return at(copy, path.subList(0, path.size() - 1)).orElseThrow();
    }

    private Object last() {
        return path.get(path.size() - 1);
    }

    private static void put(JsonNode parent, Object segment, JsonNode value) {
        if (parent instanceof ObjectNode object) {
            object.set((String) segment, value);
        } else {
            ((ArrayNode) parent).set((Integer) segment, value);
        }
    }

    private static Optional<JsonNode> at(JsonNode node, List<Object> path) {
        JsonNode current = node;
        for (Object segment : path) {
            current = segment instanceof String key ? current.get(key) : current.get((Integer) segment);
            if (current == null) {
                return Optional.empty();
            }
        }
        return Optional.of(current);
    }

    private static void collect(JsonNode node, String marker, List<Object> path, List<List<Object>> found) {
        if (node.isTextual() && node.textValue().equals(marker)) {
            found.add(List.copyOf(path));
        } else if (node.isObject()) {
            for (Map.Entry<String, JsonNode> member : node.properties()) {
                path.add(member.getKey());
                collect(member.getValue(), marker, path, found);
                path.remove(path.size() - 1);
            }
        } else if (node.isArray()) {
            for (int index = 0; index < node.size(); index++) {
                path.add(index);
                collect(node.get(index), marker, path, found);
                path.remove(path.size() - 1);
            }
        }
    }
}
