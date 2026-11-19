package com.mcpscanner.checks.shared.differential;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.ToolArgumentServer;
import com.mcpscanner.testutil.ToolArgumentServer.Outcome;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JsonSpliceTest {

    private final ToolArgumentServer server = ToolArgumentServer.of("format_invoice",
            "{\"customer\":\"Ann\",\"count\":3,\"options\":{\"currency\":\"EUR\"}}", arguments -> Outcome.ok("ok"));
    private HttpRequestResponse base;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        base = server.baseline();
    }

    @Test
    void replacesANestedValueWithAnObject() throws Exception {
        JsonSplice splice = JsonSplice.of(server.field(base, "options.currency"), base.request()).orElseThrow();

        SplicedRequest spliced = splice.withValue(JsonNodeFactory.instance.objectNode().put("$ne", "x"));

        assertThat(arguments(spliced).path("options").path("currency").path("$ne").asText()).isEqualTo("x");
        assertThat(arguments(spliced).path("customer").asText()).isEqualTo("Ann");
        assertThat(spliced.splicedText()).isEqualTo("{\"$ne\":\"x\"}");
    }

    @Test
    void addsASiblingAndRestoresTheFieldsOriginalValueAndType() throws Exception {
        JsonSplice splice = JsonSplice.of(server.field(base, "count"), base.request()).orElseThrow();

        SplicedRequest spliced = splice.withSibling("__proto__",
                JsonNodeFactory.instance.objectNode().put("k", "v")).orElseThrow();

        JsonNode arguments = arguments(spliced);
        assertThat(arguments.path("count").isInt()).isTrue();
        assertThat(arguments.path("__proto__").path("k").asText()).isEqualTo("v");
        assertThat(spliced.splicedText()).isEqualTo("\"__proto__\":{\"k\":\"v\"}");
        assertThat(splice.inObject()).isTrue();
    }

    @Test
    void refusesASiblingKeyTheObjectAlreadyHas() {
        JsonSplice splice = JsonSplice.of(server.field(base, "customer"), base.request()).orElseThrow();

        assertThat(splice.withSibling("options", JsonNodeFactory.instance.objectNode())).isEmpty();
    }

    private static JsonNode arguments(SplicedRequest spliced) throws Exception {
        return McpObjectMapper.INSTANCE.readTree(spliced.request().bodyToString()).path("params").path("arguments");
    }
}
