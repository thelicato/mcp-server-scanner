package com.mcpscanner.checks.catalog.nosqlinjection;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

enum Technique {
    NOT_EQUAL_OPERATOR("a {\"$ne\": token} object, falsified by {\"$eq\": token}", true) {
        @Override
        Payload broadening(String original, String token) {
            return operator("$ne", token);
        }

        @Override
        Payload falsifier(String original, String token) {
            return operator("$eq", token);
        }
    },
    SINGLE_QUOTED_WHERE("closing a single-quoted $where string with || 'a'=='a', falsified by 'a'=='b'", false) {
        @Override
        Payload broadening(String original, String token) {
            return new Payload.Text(token + "' || 'a'=='a");
        }

        @Override
        Payload falsifier(String original, String token) {
            return new Payload.Text(token + "' || 'a'=='b");
        }
    },
    DOUBLE_QUOTED_WHERE("closing a double-quoted $where string with || \"a\"==\"a\", falsified by \"a\"==\"b\"",
            false) {
        @Override
        Payload broadening(String original, String token) {
            return new Payload.Text(token + "\" || \"a\"==\"a");
        }

        @Override
        Payload falsifier(String original, String token) {
            return new Payload.Text(token + "\" || \"a\"==\"b");
        }
    },
    REGEX_OPERATOR("a {\"$regex\": \".*\"} object, falsified by {\"$regex\": token}", true) {
        @Override
        Payload broadening(String original, String token) {
            return operator("$regex", ".*");
        }

        @Override
        Payload falsifier(String original, String token) {
            return operator("$regex", token);
        }
    },
    SINGLE_QUOTED_WHERE_BOOLEAN("closing a single-quoted $where string with || true || '', falsified by false",
            false) {
        @Override
        Payload broadening(String original, String token) {
            return new Payload.Text(token + "' || true || '");
        }

        @Override
        Payload falsifier(String original, String token) {
            return new Payload.Text(token + "' || false || '");
        }
    },
    DOUBLE_QUOTED_WHERE_BOOLEAN("closing a double-quoted $where string with || true || \"\", falsified by false",
            false) {
        @Override
        Payload broadening(String original, String token) {
            return new Payload.Text(token + "\" || true || \"");
        }

        @Override
        Payload falsifier(String original, String token) {
            return new Payload.Text(token + "\" || false || \"");
        }
    };

    private final String described;
    private final boolean replacesValue;

    Technique(String described, boolean replacesValue) {
        this.described = described;
        this.replacesValue = replacesValue;
    }

    abstract Payload broadening(String original, String token);

    abstract Payload falsifier(String original, String token);

    String described() {
        return described;
    }

    boolean replacesValue() {
        return replacesValue;
    }

    private static Payload operator(String operator, String operand) {
        ObjectNode value = JsonNodeFactory.instance.objectNode();
        value.put(operator, operand);
        return new Payload.Value(value);
    }
}
