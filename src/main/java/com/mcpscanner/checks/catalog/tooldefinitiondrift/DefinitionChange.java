package com.mcpscanner.checks.catalog.tooldefinitiondrift;

import com.fasterxml.jackson.databind.JsonNode;

record DefinitionChange(String tool, String field, JsonNode before, JsonNode after) {

    private static final int SHOWN_CHARACTERS = 400;

    ToolField key() {
        return new ToolField(tool, field);
    }

    String describe() {
        return tool + " " + field + ": " + shown(before) + " became " + shown(after);
    }

    private static String shown(JsonNode value) {
        if (value.isMissingNode()) {
            return "(absent)";
        }
        String text = value.toString();
        return text.length() <= SHOWN_CHARACTERS ? text : text.substring(0, SHOWN_CHARACTERS) + "...";
    }
}
