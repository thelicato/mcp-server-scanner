package com.mcpscanner.checks.catalog.nosqlinjection;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.ConnectionScoped;
import com.mcpscanner.checks.api.InsertionPointCheck;
import com.mcpscanner.checks.api.RateLimitedProbing;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.api.SkipSubject;
import com.mcpscanner.checks.issue.IssueIdentity;
import com.mcpscanner.checks.shared.differential.FieldProbe;
import com.mcpscanner.checks.shared.differential.ReplyText;
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
import java.util.stream.Stream;

public final class NosqlInjectionCheck implements InsertionPointCheck, ConnectionScoped {

    static final int CONFIRMATION_ROUNDS = 2;
    static final int CORROBORATING_TECHNIQUES = 2;

    private static final SkipReason NOT_MCP = SkipReason.notApplicable("not an MCP request");
    private static final SkipReason UNREPLIED_BASELINE =
            SkipReason.prerequisiteMissing("the baseline got no JSON-RPC reply");
    private static final SkipReason UNREPLIED_CONTROL =
            SkipReason.prerequisiteMissing("a random value got no JSON-RPC reply");
    private static final SkipReason UNSTABLE = SkipReason.notApplicable(
            "the reply did not reproduce: the baseline resent or a repeat with fresh values disagreed");
    private static final SkipReason UNRESPONSIVE = SkipReason.transportFailure(
            FieldProbe.UNANSWERED_PROBES_BEFORE_GIVING_UP + " consecutive probes got no response");

    private final StreamingFallback streamedReplies;
    private final CheckLog log;
    private final RateLimitedProbing rateLimited;
    private final InsertionPointNames insertionPointNames;
    private final Supplier<String> tokens;
    private final NosqlInjectionIssues issues = new NosqlInjectionIssues(NosqlInjectionDescriptor.DESCRIPTOR);

    public NosqlInjectionCheck(BurpNativeJsonRpcFields burpNativeFields, McpEventLog eventLog,
                               OutsideBurpConnections outsideBurp) {
        this(burpNativeFields, eventLog, outsideBurp, () -> "q" + RandomHex.of(4));
    }

    NosqlInjectionCheck(BurpNativeJsonRpcFields burpNativeFields, McpEventLog eventLog,
                        OutsideBurpConnections outsideBurp, Supplier<String> tokens) {
        this.streamedReplies = outsideBurp.streamingFallback();
        this.log = new CheckLog(eventLog, NosqlInjectionDescriptor.DESCRIPTOR.id());
        this.rateLimited = new RateLimitedProbing(log);
        this.insertionPointNames = new InsertionPointNames(burpNativeFields);
        this.tokens = tokens;
    }

    @Override
    public void clearConnectionState() {
        streamedReplies.forgetStreamedRoutes();
    }

    @Override
    public CheckDescriptor descriptor() {
        return NosqlInjectionDescriptor.DESCRIPTOR;
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
        HttpRequestResponse baseline = field.baseline();
        Probe baselineProbe = new Probe(baseline, ReplyText.canonical(baseline, List.of()));
        if (baselineProbe.shape().isEmpty()) {
            log.notRun(field.described(), UNREPLIED_BASELINE);
            return Optional.empty();
        }
        List<Separation> separations = survey(field);
        if (separations.isEmpty()) {
            if (field.unresponsive()) {
                log.notRun(field.described(), UNRESPONSIVE);
            }
            return Optional.empty();
        }
        List<Probe> rounds = new ArrayList<>();
        Technique primary = separations.get(0).technique();
        for (int round = 0; round < CONFIRMATION_ROUNDS; round++) {
            HttpRequestResponse resentExchange = field.resendBaseline();
            Probe resent = new Probe(resentExchange, ReplyText.canonical(resentExchange, List.of()));
            Separation repeated = separation(field, primary, tokens.get());
            if (!resent.matches(baselineProbe) || !repeated.separates()) {
                log.notRun(field.described(), field.unresponsive() ? UNRESPONSIVE : UNSTABLE);
                return Optional.empty();
            }
            rounds.add(resent);
            rounds.addAll(repeated.probes());
        }
        List<Technique> techniques = separations.stream().map(Separation::technique).toList();
        log.info("decision: " + field.described() + " separates with " + techniques);
        return Optional.of(new Finding(techniques, separations.size() >= CORROBORATING_TECHNIQUES
                ? AuditIssueConfidence.FIRM : AuditIssueConfidence.TENTATIVE,
                Stream.of(Stream.of(baselineProbe), separations.stream().flatMap(found -> found.probes().stream()),
                        rounds.stream()).flatMap(probes -> probes).map(Probe::exchange).toList()));
    }

    private List<Separation> survey(FieldProbe field) {
        boolean splices = field.splice().isPresent();
        String token = tokens.get();
        Probe miss = Probe.sent(field, new Payload.Text(token));
        if (miss.shape().isEmpty()) {
            if (!field.gaveUp()) {
                log.notRun(field.described(), UNREPLIED_CONTROL);
            }
            return List.of();
        }
        List<Separation> separations = new ArrayList<>();
        for (Technique technique : Arrays.stream(Technique.values())
                .filter(candidate -> splices || !candidate.replacesValue()).toList()) {
            if (field.gaveUp() || separations.size() >= CORROBORATING_TECHNIQUES) {
                break;
            }
            Separation separation = new Separation(technique, miss,
                    Probe.sent(field, technique.broadening(field.original(), token)),
                    Probe.sent(field, technique.falsifier(field.original(), token)));
            if (separation.separates()) {
                separations.add(separation);
            }
        }
        return separations;
    }

    private static Separation separation(FieldProbe field, Technique technique, String token) {
        return new Separation(technique, Probe.sent(field, new Payload.Text(token)),
                Probe.sent(field, technique.broadening(field.original(), token)),
                Probe.sent(field, technique.falsifier(field.original(), token)));
    }
}
