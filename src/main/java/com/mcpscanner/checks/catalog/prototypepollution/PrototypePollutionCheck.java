package com.mcpscanner.checks.catalog.prototypepollution;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.ConnectionScoped;
import com.mcpscanner.checks.api.InsertionPointCheck;
import com.mcpscanner.checks.api.RateLimitedProbing;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.api.SkipSubject;
import com.mcpscanner.checks.issue.IssueIdentity;
import com.mcpscanner.checks.shared.differential.FieldProbe;
import com.mcpscanner.checks.shared.differential.JsonSplice;
import com.mcpscanner.checks.shared.differential.ReplyText;
import com.mcpscanner.checks.shared.differential.SplicedRequest;
import com.mcpscanner.checks.shared.evidence.PayloadHighlights;
import com.mcpscanner.checks.shared.field.InsertionPointNames;
import com.mcpscanner.checks.shared.random.RandomHex;
import com.mcpscanner.checks.shared.session.OutsideBurpConnections;
import com.mcpscanner.checks.shared.session.StreamingFallback;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.mcp.McpRequestDetector;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

public final class PrototypePollutionCheck implements InsertionPointCheck, ConnectionScoped {

    private static final String CONTROL_KEY_PREFIX = "mcpctl";
    private static final SkipReason NOT_MCP = SkipReason.notApplicable("not an MCP request");
    private static final SkipReason NOT_IN_AN_OBJECT =
            SkipReason.notApplicable("the field is not a member of a JSON object in the body");
    private static final SkipReason UNREPLIED_BASELINE =
            SkipReason.prerequisiteMissing("the baseline got no JSON-RPC reply");
    private static final SkipReason REMEMBERS_ARGUMENTS = SkipReason.notApplicable(
            "a value nested under an ordinary key also reached a later reply, so the server remembers arguments");
    private static final SkipReason UNSTABLE = SkipReason.notApplicable(
            "a repeat with a fresh property did not reach the next clean reply");
    private static final SkipReason UNRESPONSIVE = SkipReason.transportFailure(
            FieldProbe.UNANSWERED_PROBES_BEFORE_GIVING_UP + " consecutive probes got no response");

    private final StreamingFallback streamedReplies;
    private final CheckLog log;
    private final RateLimitedProbing rateLimited;
    private final InsertionPointNames insertionPointNames;
    private final Supplier<Pollutant> pollutants;
    private final PrototypePollutionIssues issues =
            new PrototypePollutionIssues(PrototypePollutionDescriptor.DESCRIPTOR);

    public PrototypePollutionCheck(BurpNativeJsonRpcFields burpNativeFields, McpEventLog eventLog,
                                   OutsideBurpConnections outsideBurp) {
        this(burpNativeFields, eventLog, outsideBurp, Pollutant::random);
    }

    PrototypePollutionCheck(BurpNativeJsonRpcFields burpNativeFields, McpEventLog eventLog,
                            OutsideBurpConnections outsideBurp, Supplier<Pollutant> pollutants) {
        this.streamedReplies = outsideBurp.streamingFallback();
        this.log = new CheckLog(eventLog, PrototypePollutionDescriptor.DESCRIPTOR.id());
        this.rateLimited = new RateLimitedProbing(log);
        this.insertionPointNames = new InsertionPointNames(burpNativeFields);
        this.pollutants = pollutants;
    }

    @Override
    public void clearConnectionState() {
        streamedReplies.forgetStreamedRoutes();
    }

    @Override
    public CheckDescriptor descriptor() {
        return PrototypePollutionDescriptor.DESCRIPTOR;
    }

    @Override
    public boolean requiresReply() {
        return true;
    }

    @Override
    public List<AuditIssue> audit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint,
                                  Http http) {
        String subject = SkipSubject.field(baseRequestResponse, insertionPoint);
        if (!McpRequestDetector.classify(baseRequestResponse).isMcp()) {
            log.notRun(subject, NOT_MCP);
            return List.of();
        }
        return rateLimited.run(subject, streamedReplies.around(http), guarded -> {
            FieldProbe field = new FieldProbe(baseRequestResponse, insertionPoint, guarded, subject);
            return probe(field).map(finding -> issues.render(finding, baseRequestResponse.request(),
                    insertionPointNames.nameOf(baseRequestResponse.request(), insertionPoint))).stream().toList();
        });
    }

    @Override
    public ConsolidationAction consolidate(AuditIssue existingIssue, AuditIssue newIssue) {
        return IssueIdentity.keepExistingWhen(IssueIdentity.sameSubject(existingIssue, newIssue));
    }

    private Optional<Finding> probe(FieldProbe field) {
        Optional<JsonSplice> splice = field.splice().filter(JsonSplice::inObject);
        if (splice.isEmpty()) {
            log.notRun(field.described(), NOT_IN_AN_OBJECT);
            return Optional.empty();
        }
        HttpRequestResponse baseline = field.baseline();
        if (ReplyText.of(baseline).isEmpty()) {
            log.notRun(field.described(), UNREPLIED_BASELINE);
            return Optional.empty();
        }
        for (Technique technique : Technique.values()) {
            if (field.gaveUp()) {
                break;
            }
            Pollutant first = pollutants.get();
            List<HttpRequestResponse> polluted = pollute(field, splice.get(), technique.key(),
                    technique.carrying(first), first);
            if (reached(polluted, first)) {
                return confirm(field, splice.get(), technique, first, baseline, polluted);
            }
        }
        if (field.unresponsive()) {
            log.notRun(field.described(), UNRESPONSIVE);
        }
        return Optional.empty();
    }

    private Optional<Finding> confirm(FieldProbe field, JsonSplice splice, Technique technique, Pollutant first,
                                      HttpRequestResponse baseline, List<HttpRequestResponse> polluted) {
        Pollutant controlled = pollutants.get();
        List<HttpRequestResponse> control = pollute(field, splice, CONTROL_KEY_PREFIX + RandomHex.of(4),
                controlled.object(), controlled);
        if (reached(control, controlled)) {
            log.notRun(field.described(), REMEMBERS_ARGUMENTS);
            return Optional.empty();
        }
        Pollutant fresh = pollutants.get();
        List<HttpRequestResponse> repeated = pollute(field, splice, technique.key(), technique.carrying(fresh), fresh);
        if (!reached(repeated, fresh)) {
            log.notRun(field.described(), field.unresponsive() ? UNRESPONSIVE : UNSTABLE);
            return Optional.empty();
        }
        log.info("decision: " + field.described() + " pollutes the prototype through " + technique.key());
        List<HttpRequestResponse> evidence = new ArrayList<>(List.of(baseline));
        evidence.addAll(polluted);
        evidence.addAll(control);
        evidence.addAll(repeated);
        return Optional.of(new Finding(technique, first, evidence));
    }

    private static List<HttpRequestResponse> pollute(FieldProbe field, JsonSplice splice, String key, JsonNode value,
                                                     Pollutant pollutant) {
        SplicedRequest spliced = splice.withSibling(key, value).orElseThrow();
        HttpRequestResponse sent = field.send(spliced);
        HttpRequestResponse later = field.resendBaseline();
        return Arrays.asList(sent, later == null ? null
                : PayloadHighlights.ofProof(later, List.of(pollutant.value())));
    }

    private static boolean reached(List<HttpRequestResponse> pollutedThenLater, Pollutant pollutant) {
        return ReplyText.of(pollutedThenLater.get(1)).filter(text -> text.contains(pollutant.value())).isPresent();
    }
}
