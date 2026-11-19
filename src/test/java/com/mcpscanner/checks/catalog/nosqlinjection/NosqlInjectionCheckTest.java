package com.mcpscanner.checks.catalog.nosqlinjection;

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

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class NosqlInjectionCheckTest {

    private static final List<String> TITLES = List.of("groceries", "standup", "roadmap");
    private static final Pattern WHERE_BREAKOUT =
            Pattern.compile("^(.*)' \\|\\| (?:'a'=='(?<cmp>[ab])|(?<bool>true|false) \\|\\| ')$");

    private final McpEventLog eventLog = new McpEventLog(null);

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void reportsOperatorsHonouredInAFilterFirmly() {
        ToolArgumentServer server = titleServer(NosqlInjectionCheckTest::mongoFilter);

        assertThat(audit(server)).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP NoSQL injection");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("find_note_by_title", "$ne", "$regex");
        });
    }

    @Test
    void reportsAWhereClauseBuiltFromAQuotedValue() {
        ToolArgumentServer server = titleServer(title -> title.isTextual() ? where(title.asText())
                : Outcome.error("SyntaxError: unexpected token"));

        assertThat(audit(server)).singleElement().satisfies(issue -> {
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("single-quoted $where", "|| true ||");
        });
    }

    @Test
    void aServerThatStringifiesAndReflectsObjectsIsNotReported() {
        ToolArgumentServer server = titleServer(title -> Outcome.ok("no note titled " + title));

        assertThat(audit(server)).isEmpty();
    }

    @Test
    void aServerThatRefusesObjectsIsNotReported() {
        ToolArgumentServer server = titleServer(title -> title.isTextual() ? listing(title.asText()::equals)
                : Outcome.error("title must be a string"));

        assertThat(audit(server)).isEmpty();
    }

    @Test
    void anUnstableBaselineIsNotReported() {
        AtomicInteger calls = new AtomicInteger();
        ToolArgumentServer server = titleServer(title -> {
            Outcome outcome = mongoFilter(title);
            return title.isTextual() && title.asText().equals("standup")
                    ? Outcome.ok(outcome.text() + " (read " + calls.incrementAndGet() + " times)") : outcome;
        });

        assertThat(audit(server)).isEmpty();
        assertThat(log()).anyMatch(line -> line.contains("did not reproduce"));
    }

    private static Outcome mongoFilter(JsonNode title) {
        if (title.isTextual()) {
            return listing(title.asText()::equals);
        }
        if (title.has("$ne")) {
            return listing(candidate -> !candidate.equals(title.get("$ne").asText()));
        }
        if (title.has("$eq")) {
            return listing(candidate -> candidate.equals(title.get("$eq").asText()));
        }
        if (title.has("$regex")) {
            Pattern pattern = Pattern.compile(title.get("$regex").asText());
            return listing(candidate -> pattern.matcher(candidate).find());
        }
        return Outcome.error("unknown operator");
    }

    private static Outcome where(String owner) {
        Matcher breakout = WHERE_BREAKOUT.matcher(owner);
        if (breakout.matches()) {
            boolean always = "a".equals(breakout.group("cmp")) || "true".equals(breakout.group("bool"));
            return listing(candidate -> always || candidate.equals(breakout.group(1)));
        }
        if (owner.chars().filter(character -> character == '\'').count() % 2 == 1) {
            return Outcome.error("SyntaxError: unterminated string");
        }
        return listing(owner::equals);
    }

    private static Outcome listing(Predicate<String> matches) {
        String found = TITLES.stream().filter(matches).collect(Collectors.joining("\n"));
        return Outcome.ok(found.isEmpty() ? "no matching note" : found);
    }

    private static ToolArgumentServer titleServer(Function<JsonNode, Outcome> behaviour) {
        return ToolArgumentServer.of("find_note_by_title", "{\"title\":\"standup\"}",
                arguments -> behaviour.apply(arguments.path("title")));
    }

    private List<AuditIssue> audit(ToolArgumentServer server) {
        HttpRequestResponse base = server.baseline();
        return new NosqlInjectionCheck(BurpNativeJsonRpcFields.ABSENT, eventLog, OutsideBurpConnections.validating())
                .audit(base, server.field(base, "title"), server.http());
    }

    private List<String> log() {
        return eventLog.snapshot().stream().map(McpEventLog.LogEntry::message).toList();
    }
}
