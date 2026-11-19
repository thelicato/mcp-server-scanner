package com.mcpscanner.checks.catalog.templateinjection;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.shared.session.OutsideBurpConnections;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.ToolArgumentServer;
import com.mcpscanner.testutil.ToolArgumentServer.Outcome;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

class TemplateInjectionCheckTest {

    private static final Pattern DOUBLE_BRACES = Pattern.compile("\\{\\{(\\d+)\\*(\\d+)}}");
    private static final Pattern DOLLAR_BRACES = Pattern.compile("\\$\\{(\\d+)\\*(\\d+)}");
    private static final Pattern ANY_PRODUCT = Pattern.compile("(\\d+)\\*(\\d+)");

    private final McpEventLog eventLog = new McpEventLog(null);

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void reportsADoubleBraceEngineFirmlyAfterTheControlAndTwoRepeats() {
        ToolArgumentServer server = signatureServer(value -> "Kind regards, " + evaluated(DOUBLE_BRACES, value));

        assertThat(audit(server)).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP server-side template injection");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("preview_signature", "params.arguments.signature", "Jinja2");
            assertThat(issue.requestResponses()).hasSize(5);
        });
        assertThat(server.received()).hasSize(4);
    }

    @Test
    void reportsADollarBraceEngineAfterTheDoubleBraceFormStaysLiteral() {
        ToolArgumentServer server = signatureServer(value -> "Hi " + evaluated(DOLLAR_BRACES, value));

        assertThat(audit(server)).singleElement()
                .satisfies(issue -> assertThat(issue.detail()).contains("FreeMarker"));
    }

    @Test
    void aServerThatReflectsTheValueIsNotReported() {
        ToolArgumentServer server = signatureServer(value -> "Kind regards, " + value);

        assertThat(audit(server)).isEmpty();
        assertThat(server.received()).hasSize(TemplateSyntax.values().length);
    }

    @Test
    void aCalculatorThatEvaluatesPlainArithmeticIsNotReported() {
        ToolArgumentServer server = signatureServer(value -> "= " + evaluated(ANY_PRODUCT, value));

        assertThat(audit(server)).isEmpty();
        assertThat(log()).anyMatch(line -> line.contains("evaluates arithmetic without template syntax"));
    }

    @Test
    void anEvaluationThatDoesNotRepeatIsNotReported() {
        AtomicInteger calls = new AtomicInteger();
        ToolArgumentServer server = signatureServer(value -> calls.incrementAndGet() == 2
                ? evaluated(DOUBLE_BRACES, value) : value);

        assertThat(audit(server)).isEmpty();
        assertThat(log()).anyMatch(line -> line.contains("was not evaluated"));
    }

    private static ToolArgumentServer signatureServer(Function<String, String> render) {
        return ToolArgumentServer.of("preview_signature", "{\"signature\":\"Ann Lee\"}",
                arguments -> Outcome.ok(render.apply(arguments.path("signature").asText())));
    }

    private static String evaluated(Pattern expression, String value) {
        Matcher matcher = expression.matcher(value);
        StringBuilder rendered = new StringBuilder();
        while (matcher.find()) {
            matcher.appendReplacement(rendered,
                    Long.toString(Long.parseLong(matcher.group(1)) * Long.parseLong(matcher.group(2))));
        }
        return matcher.appendTail(rendered).toString();
    }

    private List<AuditIssue> audit(ToolArgumentServer server) {
        HttpRequestResponse base = server.baseline();
        return new TemplateInjectionCheck(BurpNativeJsonRpcFields.ABSENT, eventLog, OutsideBurpConnections.validating())
                .audit(base, server.field(base, "signature"), server.http());
    }

    private List<String> log() {
        return eventLog.snapshot().stream().map(McpEventLog.LogEntry::message).toList();
    }
}
