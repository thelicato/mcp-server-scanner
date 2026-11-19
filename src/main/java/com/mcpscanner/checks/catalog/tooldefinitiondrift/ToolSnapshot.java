package com.mcpscanner.checks.catalog.tooldefinitiondrift;

import com.fasterxml.jackson.databind.JsonNode;

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

    boolean keeps(DefinitionChange change) {
        JsonNode definition = tools.get(change.tool());
        return definition != null && definition.path(change.field()).equals(change.after());
    }
}
