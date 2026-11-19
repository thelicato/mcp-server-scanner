package com.mcpscanner.checks.catalog.templateinjection;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
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
import com.mcpscanner.checks.shared.evidence.PayloadHighlights;
import com.mcpscanner.checks.shared.field.InsertionPointNames;
import com.mcpscanner.checks.shared.session.OutsideBurpConnections;
import com.mcpscanner.checks.shared.session.StreamingFallback;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.mcp.McpRequestDetector;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

public final class TemplateInjectionCheck implements InsertionPointCheck, ConnectionScoped {

    static final int REPEATS = 2;

    private static final SkipReason NOT_MCP = SkipReason.notApplicable("not an MCP request");
    private static final SkipReason UNREPLIED_BASELINE =
            SkipReason.prerequisiteMissing("the baseline got no JSON-RPC reply");
    private static final SkipReason EVALUATES_PLAIN_ARITHMETIC = SkipReason.notApplicable(
            "the field evaluates arithmetic without template syntax, so it is a calculator or code evaluation");
    private static final SkipReason UNSTABLE = SkipReason.notApplicable(
            "a repeat of the evaluated template expression with fresh numbers was not evaluated");
    private static final SkipReason UNRESPONSIVE = SkipReason.transportFailure(
            FieldProbe.UNANSWERED_PROBES_BEFORE_GIVING_UP + " consecutive probes got no response");

    private final StreamingFallback streamedReplies;
    private final CheckLog log;
    private final RateLimitedProbing rateLimited;
    private final InsertionPointNames insertionPointNames;
    private final Supplier<Product> products;
    private final TemplateInjectionIssues issues = new TemplateInjectionIssues(TemplateInjectionDescriptor.DESCRIPTOR);

    public TemplateInjectionCheck(BurpNativeJsonRpcFields burpNativeFields, McpEventLog eventLog,
                                  OutsideBurpConnections outsideBurp) {
        this(burpNativeFields, eventLog, outsideBurp, Product::random);
    }

    TemplateInjectionCheck(BurpNativeJsonRpcFields burpNativeFields, McpEventLog eventLog,
                           OutsideBurpConnections outsideBurp, Supplier<Product> products) {
        this.streamedReplies = outsideBurp.streamingFallback();
        this.log = new CheckLog(eventLog, TemplateInjectionDescriptor.DESCRIPTOR.id());
        this.rateLimited = new RateLimitedProbing(log);
        this.insertionPointNames = new InsertionPointNames(burpNativeFields);
        this.products = products;
    }

    @Override
    public void clearConnectionState() {
        streamedReplies.forgetStreamedRoutes();
    }

    @Override
    public CheckDescriptor descriptor() {
        return TemplateInjectionDescriptor.DESCRIPTOR;
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
        Optional<String> baselineText = ReplyText.of(baseline);
        if (baselineText.isEmpty()) {
            log.notRun(field.described(), UNREPLIED_BASELINE);
            return Optional.empty();
        }
        for (TemplateSyntax syntax : TemplateSyntax.values()) {
            if (field.gaveUp()) {
                break;
            }
            Product first = products.get();
            HttpRequestResponse evaluated = field.send(field.original() + syntax.wrap(first.expression()));
            if (evaluates(evaluated, first, baselineText.get())) {
                return confirm(field, syntax, first, List.of(baseline, proven(evaluated, first)), baselineText.get());
            }
        }
        if (field.unresponsive()) {
            log.notRun(field.described(), UNRESPONSIVE);
        }
        return Optional.empty();
    }

    private Optional<Finding> confirm(FieldProbe field, TemplateSyntax syntax, Product first,
                                      List<HttpRequestResponse> found, String baselineText) {
        List<HttpRequestResponse> evidence = new ArrayList<>(found);
        Product plain = products.get();
        HttpRequestResponse arithmetic = field.send(field.original() + plain.expression());
        if (evaluates(arithmetic, plain, baselineText)) {
            log.notRun(field.described(), EVALUATES_PLAIN_ARITHMETIC);
            return Optional.empty();
        }
        evidence.add(arithmetic);
        for (int repeat = 0; repeat < REPEATS; repeat++) {
            Product fresh = products.get();
            HttpRequestResponse repeated = field.send(field.original() + syntax.wrap(fresh.expression()));
            if (!evaluates(repeated, fresh, baselineText)) {
                log.notRun(field.described(), field.unresponsive() ? UNRESPONSIVE : UNSTABLE);
                return Optional.empty();
            }
            evidence.add(proven(repeated, fresh));
        }
        log.info("decision: " + field.described() + " evaluates " + syntax.wrap("expression") + " template syntax");
        return Optional.of(new Finding(syntax, first, evidence));
    }

    private static boolean evaluates(HttpRequestResponse exchange, Product product, String baselineText) {
        return !baselineText.contains(product.value())
                && ReplyText.of(exchange).filter(text -> text.contains(product.value())).isPresent();
    }

    private static HttpRequestResponse proven(HttpRequestResponse exchange, Product product) {
        return PayloadHighlights.ofProof(exchange, List.of(product.value()));
    }
}
