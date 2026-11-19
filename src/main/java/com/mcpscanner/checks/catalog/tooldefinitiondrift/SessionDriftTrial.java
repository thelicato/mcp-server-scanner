package com.mcpscanner.checks.catalog.tooldefinitiondrift;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.HostSettlement;
import com.mcpscanner.checks.api.HostTrial;
import com.mcpscanner.checks.api.HostTrialResult;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.shared.session.ProbeSessions;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;

final class SessionDriftTrial implements HostTrial {

    static final SkipReason LEGACY_SSE =
            SkipReason.notApplicable("the legacy SSE transport has no Streamable HTTP probe sessions");
    static final SkipReason NO_SESSION = SkipReason.prerequisiteMissing("no probe session could be opened");
    static final SkipReason NO_TOOLS = SkipReason.notApplicable("the server lists no tools");
    static final SkipReason UNANSWERED = SkipReason.transportFailure("a probe tools/list got no answer");
    private static final SkipReason NOT_A_TOOL_CALL =
            SkipReason.notApplicable("needs a tools/call to replay in its own session");
    private static final SkipReason MAY_WRITE = SkipReason.notApplicable(
            "the scanned tool is not annotated read-only, so its call is not replayed");
    private static final SkipReason CALL_UNANSWERED =
            SkipReason.transportFailure("the replayed tools/call got no answer");

    private final CheckLog log;
    private final Supplier<Optional<HttpService>> sseProbeService;
    private final ProbeSessions sessions;
    private final ToolDefinitionDriftIssues issues;

    SessionDriftTrial(CheckLog log, Supplier<Optional<HttpService>> sseProbeService, ProbeSessions sessions,
                      ToolDefinitionDriftIssues issues) {
        this.log = log;
        this.sseProbeService = sseProbeService;
        this.sessions = sessions;
        this.issues = issues;
    }

    @Override
    public Optional<SkipReason> whyNotApplicable(HttpRequestResponse hostBaseRequestResponse) {
        if (sseProbeService.get().isPresent()) {
            return Optional.of(LEGACY_SSE);
        }
        return SeedCall.of(hostBaseRequestResponse.request()).isPresent()
                ? Optional.empty() : Optional.of(NOT_A_TOOL_CALL);
    }

    @Override
    public HostTrialResult run(HttpRequestResponse hostBaseRequestResponse, Http http) {
        SeedCall seed = SeedCall.of(hostBaseRequestResponse.request()).orElseThrow();
        ToolSession.Opening opening = ToolSession.open(sessions, hostBaseRequestResponse, http, log);
        if (opening.session().isEmpty()) {
            return opening.rateLimited()
                    ? stop(hostBaseRequestResponse, SkipReason.rateLimited(), HostSettlement.SETTLED)
                    : stop(hostBaseRequestResponse, NO_SESSION, HostSettlement.INCONCLUSIVE);
        }
        try (ToolSession session = opening.session().get()) {
            return run(hostBaseRequestResponse, seed, session);
        }
    }

    private HostTrialResult run(HttpRequestResponse base, SeedCall seed, ToolSession session) {
        Listing first = session.list();
        if (first.failed()) {
            return stop(base, first);
        }
        if (first.tools().isEmpty()) {
            return stop(base, NO_TOOLS, HostSettlement.SETTLED);
        }
        if (first.tools().mayWrite(seed.tool())) {
            return stop(base, MAY_WRITE, HostSettlement.UNSUITABLE_SEED);
        }
        Listing control = session.list();
        if (control.failed()) {
            return stop(base, control);
        }
        Set<ToolField> unstable = first.tools().unstableAgainst(control.tools());
        Reply call = session.call(seed.params());
        if (call.rateLimited()) {
            return stop(base, SkipReason.rateLimited(), HostSettlement.SETTLED);
        }
        if (!call.responded()) {
            return stop(base, CALL_UNANSWERED, HostSettlement.INCONCLUSIVE);
        }
        Listing after = session.list();
        if (after.failed()) {
            return stop(base, after);
        }
        boolean announced = call.announcesListChange() || after.announcesListChange();
        List<DefinitionChange> changes = control.tools().changesTo(after.tools(), unstable);
        if (changes.isEmpty()) {
            log.info("decision: no tool definition changed after calling " + seed.tool()
                    + (announced ? " (the server announced a tool list change)" : "") + volatility(unstable));
            return new HostTrialResult(List.of(), HostSettlement.UNSUITABLE_SEED);
        }
        Listing confirmation = session.list();
        if (confirmation.failed()) {
            return stop(base, confirmation);
        }
        List<DefinitionChange> lasting = changes.stream().filter(confirmation.tools()::keeps).toList();
        if (lasting.isEmpty()) {
            log.info("decision: definitions changed after calling " + seed.tool() + " but not on the next listing");
            return new HostTrialResult(List.of(), HostSettlement.UNSUITABLE_SEED);
        }
        log.info("decision: " + lasting.size() + " tool definition field(s) changed after calling " + seed.tool()
                + (announced ? ", announced with " : ", without ") + Reply.LIST_CHANGED);
        List<HttpRequestResponse> evidence = Stream.of(control.firstExchange(), call.exchange(), after.firstExchange())
                .flatMap(Optional::stream).toList();
        return HostTrialResult.settled(List.of(issues.redefined(base.request().url(), seed.tool(), announced, lasting,
                evidence)));
    }

    private HostTrialResult stop(HttpRequestResponse base, Listing failed) {
        return failed.rateLimited()
                ? stop(base, SkipReason.rateLimited(), HostSettlement.SETTLED)
                : stop(base, UNANSWERED, HostSettlement.INCONCLUSIVE);
    }

    private HostTrialResult stop(HttpRequestResponse base, SkipReason reason, HostSettlement settlement) {
        log.notRun(subject(base), reason);
        return new HostTrialResult(List.of(), settlement);
    }

    private static String volatility(Set<ToolField> unstable) {
        return unstable.isEmpty() ? "" : "; " + unstable.size() + " field(s) changed between two plain listings and "
                + "were ignored";
    }
}
