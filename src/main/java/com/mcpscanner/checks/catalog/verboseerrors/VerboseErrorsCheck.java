package com.mcpscanner.checks.catalog.verboseerrors;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.ConnectionScoped;
import com.mcpscanner.checks.api.RateLimitedProbing;
import com.mcpscanner.checks.api.RequestCheck;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.api.SkipSubject;
import com.mcpscanner.checks.issue.IssueIdentity;
import com.mcpscanner.checks.shared.evidence.PayloadHighlights;
import com.mcpscanner.checks.shared.jsonrpc.JsonRpcEnvelope;
import com.mcpscanner.checks.shared.jsonrpc.JsonRpcMessages;
import com.mcpscanner.checks.shared.session.OutsideBurpConnections;
import com.mcpscanner.checks.shared.session.StreamingFallback;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.TooManyRequests;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class VerboseErrorsCheck implements RequestCheck, ConnectionScoped {

    static final int MAX_SCANNED_CHARACTERS = 1_048_576;

    private static final SkipReason NOT_A_JSON_RPC_REQUEST =
            SkipReason.notApplicable("needs a single JSON-RPC 2.0 request with an id");
    private static final SkipReason UNSTABLE = SkipReason.notApplicable(
            "a resend of the most revealing probe did not disclose the same kind of detail again");

    private final StreamingFallback streamedReplies;
    private final CheckLog log;
    private final RateLimitedProbing rateLimited;
    private final VerboseErrorsIssues issues = new VerboseErrorsIssues(VerboseErrorsDescriptor.DESCRIPTOR);

    public VerboseErrorsCheck(McpEventLog eventLog, OutsideBurpConnections outsideBurp) {
        this.streamedReplies = outsideBurp.streamingFallback();
        this.log = new CheckLog(eventLog, VerboseErrorsDescriptor.DESCRIPTOR.id());
        this.rateLimited = new RateLimitedProbing(log);
    }

    @Override
    public void clearConnectionState() {
        streamedReplies.forgetStreamedRoutes();
    }

    @Override
    public CheckDescriptor descriptor() {
        return VerboseErrorsDescriptor.DESCRIPTOR;
    }

    @Override
    public boolean requiresReply() {
        return true;
    }

    @Override
    public List<AuditIssue> audit(HttpRequestResponse baseRequestResponse, Http http) {
        String subject = SkipSubject.of(baseRequestResponse);
        Optional<ObjectNode> message = request(baseRequestResponse.request());
        if (message.isEmpty()) {
            log.notRun(subject, NOT_A_JSON_RPC_REQUEST);
            return List.of();
        }
        return rateLimited.run(subject, streamedReplies.around(http),
                guarded -> probe(baseRequestResponse, message.get(), guarded, subject));
    }

    @Override
    public ConsolidationAction consolidate(AuditIssue existingIssue, AuditIssue newIssue) {
        return IssueIdentity.keepExistingWhen(IssueIdentity.sameSubject(existingIssue, newIssue));
    }

    private List<AuditIssue> probe(HttpRequestResponse base, ObjectNode message, Http http, String subject) {
        HttpRequestResponse baseline = base.response() != null ? base : http.sendRequest(base.request());
        String baselineText = text(baseline);
        String original = base.request().bodyToString();
        List<Leak> leaks = new ArrayList<>();
        Map<Malformation, HttpRequest> sent = new EnumMap<>(Malformation.class);
        for (Malformation malformation : Malformation.values()) {
            Optional<ObjectNode> malformed = malformation.applyTo(message);
            if (malformed.isEmpty()) {
                continue;
            }
            HttpRequest request = base.request().withBody(malformed.get().toString());
            sent.put(malformation, request);
            HttpRequestResponse exchange = http.sendRequest(request);
            if (TooManyRequests.answered(exchange)) {
                return List.of();
            }
            Map<Disclosure, List<String>> disclosed = disclosed(exchange, baselineText, original,
                    request.bodyToString());
            if (!disclosed.isEmpty()) {
                leaks.add(new Leak(malformation, disclosed, proven(exchange, disclosed)));
            }
        }
        if (leaks.isEmpty()) {
            return List.of();
        }
        Leak strongest = leaks.stream().max(Comparator.comparingInt(Leak::strength)).orElseThrow();
        HttpRequest repeat = sent.get(strongest.malformation());
        HttpRequestResponse resent = http.sendRequest(repeat);
        Map<Disclosure, List<String>> again = disclosed(resent, baselineText, original, repeat.bodyToString());
        if (again.keySet().stream().noneMatch(strongest.disclosures()::containsKey)) {
            if (!TooManyRequests.answered(resent)) {
                log.notRun(subject, UNSTABLE);
            }
            return List.of();
        }
        log.info("decision: " + subject + " discloses " + strongest.disclosures().keySet() + " when sent "
                + strongest.malformation().described());
        List<HttpRequestResponse> evidence = new ArrayList<>(List.of(baseline));
        leaks.forEach(leak -> evidence.add(leak.exchange()));
        evidence.add(proven(resent, again));
        return List.of(issues.render(base.request(), leaks, evidence));
    }

    private static Map<Disclosure, List<String>> disclosed(HttpRequestResponse exchange, String baselineText,
                                                           String original, String probe) {
        String text = text(exchange);
        Map<Disclosure, List<String>> disclosed = new EnumMap<>(Disclosure.class);
        for (Disclosure disclosure : Disclosure.values()) {
            List<String> fresh = disclosure.matchesIn(text).stream()
                    .filter(match -> !baselineText.contains(match) && !original.contains(match)
                            && !probe.contains(match))
                    .distinct()
                    .toList();
            if (!fresh.isEmpty()) {
                disclosed.put(disclosure, fresh);
            }
        }
        return disclosed;
    }

    private static String text(HttpRequestResponse exchange) {
        if (exchange == null || exchange.response() == null) {
            return "";
        }
        String body = exchange.response().bodyToString();
        String bounded = body.length() > MAX_SCANNED_CHARACTERS ? body.substring(0, MAX_SCANNED_CHARACTERS) : body;
        List<JsonNode> messages = JsonRpcMessages.in(bounded);
        if (messages.isEmpty()) {
            return bounded;
        }
        StringBuilder text = new StringBuilder();
        messages.forEach(message -> appendText(message, text));
        return text.toString();
    }

    private static void appendText(JsonNode node, StringBuilder text) {
        if (node.isTextual()) {
            text.append(node.textValue()).append('\n');
        } else if (node.isContainerNode()) {
            node.forEach(child -> appendText(child, text));
        }
    }

    private static HttpRequestResponse proven(HttpRequestResponse exchange, Map<Disclosure, List<String>> found) {
        return exchange == null ? null : PayloadHighlights.ofProof(exchange,
                found.values().stream().flatMap(List::stream).toList());
    }

    private static Optional<ObjectNode> request(HttpRequest request) {
        JsonRpcEnvelope envelope = JsonRpcEnvelope.of(request);
        if (!envelope.isJsonRpc2() || !envelope.singleMessage() || !envelope.hasScalarId()
                || envelope.method().isEmpty()) {
            return Optional.empty();
        }
        return envelope.root().filter(ObjectNode.class::isInstance).map(ObjectNode.class::cast);
    }
}
