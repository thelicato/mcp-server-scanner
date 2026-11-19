package com.mcpscanner.checks.catalog.tooldefinitiondrift;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ToolAnnotations;
import com.mcpscanner.mcp.ToolSafety;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

record ToolSnapshot(Map<String, JsonNode> tools) {

    static final List<String> FIELDS = List.of("title", "description", "inputSchema", "outputSchema", "annotations");

    ToolSnapshot {
        tools = Collections.unmodifiableMap(new LinkedHashMap<>(tools));
    }

    boolean isEmpty() {
        return tools.isEmpty();
    }

    List<DefinitionChange> changesTo(ToolSnapshot later, Set<ToolField> ignored) {
        List<DefinitionChange> changes = new ArrayList<>();
        tools.forEach((name, definition) -> {
            JsonNode changed = later.tools.get(name);
            if (changed == null) {
                return;
            }
            for (String field : FIELDS) {
                JsonNode before = definition.path(field);
                JsonNode after = changed.path(field);
                if (!before.equals(after) && !ignored.contains(new ToolField(name, field))) {
                    changes.add(new DefinitionChange(name, field, before, after));
                }
            }
        });
        return changes;
    }

    Set<ToolField> unstableAgainst(ToolSnapshot again) {
        return changesTo(again, Set.of()).stream().map(DefinitionChange::key).collect(Collectors.toSet());
    }

    boolean mayWrite(String tool) {
        JsonNode definition = tools.get(tool);
        if (definition == null) {
            return true;
        }
        JsonNode annotations = definition.path("annotations");
        return ToolSafety.mayWrite(new McpToolDefinition(tool, definition.path("description").asText(""),
                definition.path("inputSchema").toString(), List.of(), new ToolAnnotations(
                        annotations.path("title").asText(null), hint(annotations, "readOnlyHint"),
                        hint(annotations, "destructiveHint"), hint(annotations, "idempotentHint"),
                        hint(annotations, "openWorldHint"))));
    }

    boolean keeps(DefinitionChange change) {
        JsonNode definition = tools.get(change.tool());
        return definition != null && definition.path(change.field()).equals(change.after());
    }

    private static Boolean hint(JsonNode annotations, String name) {
        JsonNode hint = annotations.path(name);
        return hint.isBoolean() ? hint.booleanValue() : null;
    }
}
