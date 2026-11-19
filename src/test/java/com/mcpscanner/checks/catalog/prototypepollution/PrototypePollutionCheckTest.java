package com.mcpscanner.checks.catalog.prototypepollution;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.checks.shared.session.OutsideBurpConnections;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.ToolArgumentServer;
import com.mcpscanner.testutil.ToolArgumentServer.Outcome;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class PrototypePollutionCheckTest {

    private static final String ARGUMENTS = "{\"customer\":\"Ann\",\"options\":{\"currency\":\"EUR\"}}";

    private final McpEventLog eventLog = new McpEventLog(null);

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void reportsAMergeThatFollowsProtoFirmly() {
        ToolArgumentServer server = invoiceServer(new PollutableRealm(true, true));

        assertThat(audit(server, "customer")).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP server-side prototype pollution");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("format_invoice", "&quot;__proto__&quot;");
            assertThat(issue.requestResponses()).hasSize(7);
        });
        assertThat(server.received().get(0).has("__proto__")).isTrue();
        assertThat(server.received().get(1).has("__proto__")).isFalse();
    }

    @Test
    void reportsAMergeThatOnlyFollowsConstructorPrototype() {
        ToolArgumentServer server = invoiceServer(new PollutableRealm(false, true));

        assertThat(audit(server, "options.currency")).singleElement()
                .satisfies(issue -> assertThat(issue.detail()).contains("&quot;constructor&quot;"));
    }

    @Test
    void aGuardedMergeIsNotReportedAfterTwoProbesAndTheirCleanResends() {
        ToolArgumentServer server = invoiceServer(new PollutableRealm(false, false));

        assertThat(audit(server, "customer")).isEmpty();
        assertThat(server.received()).hasSize(4);
    }

    @Test
    void aServerThatRemembersTheLastArgumentsIsNotReported() {
        AtomicReference<JsonNode> previous = new AtomicReference<>();
        ToolArgumentServer server = ToolArgumentServer.of("format_invoice", ARGUMENTS,
                arguments -> Outcome.ok("Invoice for " + arguments.path("customer").asText()
                        + "; previous arguments " + previous.getAndSet(arguments)));

        assertThat(audit(server, "customer")).isEmpty();
        assertThat(log()).anyMatch(line -> line.contains("the server remembers arguments"));
    }

    private static ToolArgumentServer invoiceServer(PollutableRealm realm) {
        return ToolArgumentServer.of("format_invoice", ARGUMENTS, realm::format);
    }

    private List<AuditIssue> audit(ToolArgumentServer server, String field) {
        HttpRequestResponse base = server.baseline();
        return new PrototypePollutionCheck(BurpNativeJsonRpcFields.ABSENT, eventLog,
                OutsideBurpConnections.validating()).audit(base, server.field(base, field), server.http());
    }

    private List<String> log() {
        return eventLog.snapshot().stream().map(McpEventLog.LogEntry::message).toList();
    }

    private static final class PollutableRealm {

        private final boolean followsProto;
        private final boolean followsConstructor;
        private final Map<String, String> objectPrototype = new LinkedHashMap<>();

        PollutableRealm(boolean followsProto, boolean followsConstructor) {
            this.followsProto = followsProto;
            this.followsConstructor = followsConstructor;
        }

        Outcome format(JsonNode arguments) {
            pollute(arguments);
            pollute(arguments.path("options"));
            StringBuilder text = new StringBuilder("Invoice for " + arguments.path("customer").asText());
            objectPrototype.forEach((key, value) -> text.append('\n').append(key).append(" = ").append(value));
            return Outcome.ok(text.toString());
        }

        private void pollute(JsonNode object) {
            if (followsProto) {
                object.path("__proto__").properties().forEach(member ->
                        objectPrototype.put(member.getKey(), member.getValue().asText()));
            }
            if (followsConstructor) {
                object.path("constructor").path("prototype").properties().forEach(member ->
                        objectPrototype.put(member.getKey(), member.getValue().asText()));
            }
        }
    }
}
