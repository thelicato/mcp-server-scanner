package com.mcpscanner.checks.catalog.tokenpassthrough;

import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.ConnectionScoped;
import com.mcpscanner.checks.api.InsertionPointCheck;
import com.mcpscanner.checks.api.LateIssueSink;
import com.mcpscanner.checks.api.RateLimitedProbing;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.api.SkipSubject;
import com.mcpscanner.checks.issue.IssueIdentity;
import com.mcpscanner.checks.shared.collaborator.CollaboratorWatch;
import com.mcpscanner.checks.shared.collaborator.InteractionDescription;
import com.mcpscanner.checks.shared.collaborator.ObservedInteractions;
import com.mcpscanner.checks.shared.collaborator.WatchDecision;
import com.mcpscanner.checks.shared.evidence.PayloadHighlights;
import com.mcpscanner.checks.shared.field.InsertionPointNames;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

public final class TokenPassthroughCheck implements InsertionPointCheck, ConnectionScoped {

    private static final SkipReason NOT_A_URL_FIELD =
            SkipReason.notApplicable("not an MCP field or header that takes a URL or host");
    private static final SkipReason NO_CLIENT_CREDENTIAL = SkipReason.notApplicable(
            "the scanning user sends no credential of " + ClientCredentials.MINIMUM_LENGTH + " or more characters");
    private static final SkipReason COLLABORATOR_UNAVAILABLE =
            SkipReason.prerequisiteMissing("Burp Collaborator is unavailable");
    private static final SkipReason ALREADY_CONFIRMED = SkipReason.alreadyAudited(
            "the client's credential already reached another host from this field at this endpoint");
    private static final SkipReason NO_PAYLOAD = SkipReason.prerequisiteMissing("Burp Collaborator issued no payload");

    private final CheckLog log;
    private final RateLimitedProbing rateLimited;
    private final Supplier<AuthStrategy> authStrategy;
    private final CollaboratorWatch watch;
    private final LateIssueSink lateIssues;
    private final InsertionPointNames names;
    private final TokenPassthroughIssues issues = new TokenPassthroughIssues(TokenPassthroughDescriptor.DESCRIPTOR);
    private final AtomicReference<Set<String>> confirmed = new AtomicReference<>(ConcurrentHashMap.newKeySet());

    public TokenPassthroughCheck(McpEventLog eventLog, Supplier<AuthStrategy> authStrategy, CollaboratorWatch watch,
                                 LateIssueSink lateIssues, BurpNativeJsonRpcFields burpNativeFields) {
        this.log = new CheckLog(eventLog, TokenPassthroughDescriptor.DESCRIPTOR.id());
        this.rateLimited = new RateLimitedProbing(log);
        this.authStrategy = authStrategy;
        this.watch = watch;
        this.lateIssues = lateIssues;
        this.names = new InsertionPointNames(burpNativeFields);
    }

    @Override
    public CheckDescriptor descriptor() {
        return TokenPassthroughDescriptor.DESCRIPTOR;
    }

    @Override
    public List<AuditIssue> audit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint,
                                  Http http) {
        String subject = SkipSubject.field(baseRequestResponse, insertionPoint);
        Optional<UrlField> field = UrlField.of(baseRequestResponse.request(), insertionPoint, names);
        ClientCredentials credentials = ClientCredentials.of(authStrategy.get().currentHeaders());
        Optional<SkipReason> skip = skipReason(baseRequestResponse, field, credentials);
        if (skip.isPresent()) {
            notRun(subject, skip.get());
            return List.of();
        }
        return rateLimited.run(subject, http, guarded -> {
            probe(baseRequestResponse, insertionPoint, field.get(), credentials, guarded);
            return List.of();
        });
    }

    @Override
    public ConsolidationAction consolidate(AuditIssue existingIssue, AuditIssue newIssue) {
        return IssueIdentity.keepStrongerOfSameSubject(existingIssue, newIssue);
    }

    @Override
    public void clearConnectionState() {
        confirmed.set(ConcurrentHashMap.newKeySet());
    }

    private void notRun(String subject, SkipReason reason) {
        if (reason == COLLABORATOR_UNAVAILABLE) {
            log.notRunOncePerLoad(subject, reason);
        } else {
            log.notRun(subject, reason);
        }
    }

    private Optional<SkipReason> skipReason(HttpRequestResponse base, Optional<UrlField> field,
                                            ClientCredentials credentials) {
        if (field.isEmpty()) {
            return Optional.of(NOT_A_URL_FIELD);
        }
        if (credentials.isEmpty()) {
            return Optional.of(NO_CLIENT_CREDENTIAL);
        }
        if (!watch.available()) {
            return Optional.of(COLLABORATOR_UNAVAILABLE);
        }
        if (confirmed.get().contains(subjectKey(base, field.get()))) {
            return Optional.of(ALREADY_CONFIRMED);
        }
        return Optional.empty();
    }

    private void probe(HttpRequestResponse base, AuditInsertionPoint point, UrlField field,
                       ClientCredentials credentials, Http http) {
        Set<String> connectionConfirmed = confirmed.get();
        Optional<SentProbe> sent = watch.probing(payloads -> payloads.newPayload()
                .map(host -> send(point, field, host, http)));
        if (sent.isEmpty()) {
            log.notRun(SkipSubject.field(base, point), NO_PAYLOAD);
            return;
        }
        HttpRequestResponse keptBase = watch.kept(base);
        SentProbe probe = new SentProbe(sent.get().payload(), sent.get().value(), watch.kept(sent.get().exchange()));
        watch.watch(List.of(probe.payload()), soFar -> forwarded(soFar, probe, credentials).map(found -> {
            if (connectionConfirmed.add(subjectKey(keptBase, field))) {
                AuditIssue issue = issues.forwarded(keptBase, SkipSubject.field(keptBase, point), probe.value(),
                        probe.exchange(), found.callback(), found.places(), found.credentials().redactor());
                log.info("reported " + issue.name() + " for " + field.name());
                lateIssues.report(this, List.of(issue));
            }
            return WatchDecision.DONE;
        }).orElse(WatchDecision.KEEP_WATCHING));
    }

    private Optional<Forwarded> forwarded(ObservedInteractions soFar, SentProbe probe, ClientCredentials atProbe) {
        List<ClientCredentials> candidates = List.of(atProbe,
                ClientCredentials.of(authStrategy.get().currentHeaders()));
        for (Interaction interaction : soFar.of(probe.payload())) {
            Optional<HttpRequest> callback = InteractionDescription.httpRequestOf(interaction);
            for (ClientCredentials credentials : candidates) {
                List<String> places = callback.map(credentials::foundIn).orElse(List.of());
                if (!places.isEmpty()) {
                    return Optional.of(new Forwarded(callback.get(), places, credentials));
                }
            }
        }
        return Optional.empty();
    }

    private static SentProbe send(AuditInsertionPoint point, UrlField field, CollaboratorPayload host, Http http) {
        String value = field.probe(host.toString());
        HttpRequest request = point.buildHttpRequestWithPayload(ByteArray.byteArray(value));
        return new SentProbe(host, value, PayloadHighlights.ofPayload(exchange(http, request), point, value));
    }

    private static HttpRequestResponse exchange(Http http, HttpRequest probe) {
        try {
            return http.sendRequest(probe);
        } catch (RuntimeException failure) {
            return HttpRequestResponse.httpRequestResponse(probe, null);
        }
    }

    private static String subjectKey(HttpRequestResponse base, UrlField field) {
        return base.request().url() + "\n" + field.name();
    }

    private record SentProbe(CollaboratorPayload payload, String value, HttpRequestResponse exchange) {
    }

    private record Forwarded(HttpRequest callback, List<String> places, ClientCredentials credentials) {
    }
}
