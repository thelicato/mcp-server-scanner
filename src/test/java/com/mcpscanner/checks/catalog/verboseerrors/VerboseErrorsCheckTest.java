package com.mcpscanner.checks.catalog.verboseerrors;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.checks.shared.session.OutsideBurpConnections;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.ToolArgumentServer;
import com.mcpscanner.testutil.ToolArgumentServer.Outcome;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

class VerboseErrorsCheckTest {

    private static final String ARGUMENTS = "{\"celsius\":20,\"scale\":\"fahrenheit\"}";
    private static final String PYTHON_TRACE = "Internal error\nTraceback (most recent call last):\n"
            + "  File \"/app/server/tools.py\", line 41, in convert\n    return SCALES[scale](float(celsius))\n"
            + "KeyError: 'x'\nserved by Python 3.11.9";
    private static final String NODE_TRACE = "TypeError: celsius.toFixed is not a function\n"
            + "    at convert (/srv/mcp/tools.js:12:7)\n    at async handle (/srv/mcp/node_modules/sdk/server.js:88:3)";

    private final McpEventLog eventLog = new McpEventLog(null);

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void reportsAPythonTracebackWithItsPathsAndVersion() {
        ToolArgumentServer server = converter(bad -> Outcome.error(PYTHON_TRACE));

        assertThat(audit(server)).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP verbose error messages");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("convert_temperature", "a stack trace", "a server source file path",
                    "a framework or runtime version", "/app/server/tools.py");
            assertThat(issue.requestResponses()).hasSize(6);
        });
        assertThat(server.received()).hasSize(5);
    }

    @Test
    void reportsANodeStackTrace() {
        assertThat(audit(converter(bad -> Outcome.error(NODE_TRACE)))).singleElement().satisfies(issue ->
                assertThat(issue.detail()).contains("a stack trace", "/srv/mcp/tools.js"));
    }

    @Test
    void aVersionAloneIsInformation() {
        ToolArgumentServer server = converter(bad -> Outcome.error("1 validation error: Input should be a valid "
                + "number. For further information visit https://errors.pydantic.dev/2.11/v/float_parsing"));

        assertThat(audit(server)).singleElement()
                .satisfies(issue -> assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION));
    }

    @Test
    void aShortErrorIsNotReportedAfterFourProbes() {
        ToolArgumentServer server = converter(bad -> Outcome.error("Error: celsius must be a number"));

        assertThat(audit(server)).isEmpty();
        assertThat(server.received()).hasSize(4);
    }

    @Test
    void aPathTheRequestItselfCarriesIsNotADisclosure() {
        ToolArgumentServer server = ToolArgumentServer.of("read_file", "{\"path\":\"/home/ann/notes.py\"}",
                arguments -> Outcome.error("cannot open /home/ann/notes.py"));

        assertThat(audit(server)).isEmpty();
    }

    @Test
    void aVersionTheBaselineAlreadyShowsIsNotADisclosure() {
        ToolArgumentServer server = ToolArgumentServer.of("convert_temperature", ARGUMENTS, arguments ->
                valid(arguments) ? Outcome.ok("68.00 (Python 3.11.9)") : Outcome.error("bad input (Python 3.11.9)"));

        assertThat(audit(server)).isEmpty();
    }

    @Test
    void aUrlIsNotAServerPath() {
        assertThat(audit(converter(bad -> Outcome.error("see https://docs.example/app/convert.js for usage"))))
                .isEmpty();
    }

    @Test
    void aDisclosureThatDoesNotRepeatIsNotReported() {
        AtomicInteger errors = new AtomicInteger();
        ToolArgumentServer server = converter(bad -> errors.incrementAndGet() == 1
                ? Outcome.error(PYTHON_TRACE) : Outcome.error("Error: try again"));

        assertThat(audit(server)).isEmpty();
        assertThat(log()).anyMatch(line -> line.contains("did not disclose the same kind of detail again"));
    }

    @Test
    void aNotificationIsNotApplicable() {
        HttpRequestResponse notification = HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequestFromUrl(ToolArgumentServer.ENDPOINT).withMethod("POST")
                        .withBody("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}"), null);

        assertThat(check().audit(notification, converter(bad -> Outcome.error(PYTHON_TRACE)).http())).isEmpty();
        assertThat(log()).anyMatch(line -> line.contains("needs a single JSON-RPC 2.0 request with an id"));
    }

    private static ToolArgumentServer converter(Function<JsonNode, Outcome> onBadArguments) {
        return ToolArgumentServer.of("convert_temperature", ARGUMENTS,
                arguments -> valid(arguments) ? Outcome.ok("68.00") : onBadArguments.apply(arguments));
    }

    private static boolean valid(JsonNode arguments) {
        return arguments.path("celsius").isNumber() && arguments.path("scale").isTextual()
                && List.of("fahrenheit", "kelvin").contains(arguments.path("scale").asText());
    }

    private List<AuditIssue> audit(ToolArgumentServer server) {
        return check().audit(server.baseline(), server.http());
    }

    private VerboseErrorsCheck check() {
        return new VerboseErrorsCheck(eventLog, OutsideBurpConnections.validating());
    }

    private List<String> log() {
        return eventLog.snapshot().stream().map(McpEventLog.LogEntry::message).toList();
    }
}
