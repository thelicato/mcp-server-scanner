package com.mcpscanner.checks.catalog.tooldefinitiondrift;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.HostSettlement;
import com.mcpscanner.checks.api.HostTrial;
import com.mcpscanner.checks.api.HostTrialResult;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.api.crossidentity.ComparedPrincipals;
import com.mcpscanner.checks.shared.session.OutsideBurpConnections;
import com.mcpscanner.checks.shared.session.ProbeSessions;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Stream;

final class UserDriftTrial implements HostTrial {

    private static final SkipReason NO_COMPARED_USERS =
            SkipReason.notApplicable("no compared user with credentials is configured");
    private static final SkipReason NO_COMPARED_LISTING =
            SkipReason.transportFailure("no compared user's tools/list was answered");

    private final CheckLog log;
    private final Supplier<Optional<HttpService>> sseProbeService;
    private final Supplier<PrincipalRoster> principals;
    private final ProbeSessions primarySessions;
    private final Function<AuthStrategy, ProbeSessions> userSessions;
    private final ToolDefinitionDriftIssues issues;

    UserDriftTrial(CheckLog log, Supplier<Optional<HttpService>> sseProbeService, Supplier<PrincipalRoster> principals,
                   Supplier<AuthStrategy> primaryAuth, OutsideBurpConnections outsideBurp,
                   ToolDefinitionDriftIssues issues) {
        this.log = log;
        this.sseProbeService = sseProbeService;
        this.principals = principals;
        this.primarySessions = new ProbeSessions(primaryAuth, outsideBurp);
        this.userSessions = auth -> new ProbeSessions(() -> auth, outsideBurp);
        this.issues = issues;
    }

    @Override
    public Optional<SkipReason> whyNotApplicable(HttpRequestResponse hostBaseRequestResponse) {
        if (sseProbeService.get().isPresent()) {
            return Optional.of(SessionDriftTrial.LEGACY_SSE);
        }
        return compared().isEmpty() ? Optional.of(NO_COMPARED_USERS) : Optional.empty();
    }

    @Override
    public HostTrialResult run(HttpRequestResponse hostBaseRequestResponse, Http http) {
        Listing baseline = ToolSession.listOnce(primarySessions, hostBaseRequestResponse, http, log);
        if (baseline.failed()) {
            return stop(hostBaseRequestResponse, baseline);
        }
        if (baseline.tools().isEmpty()) {
            return stop(hostBaseRequestResponse, SessionDriftTrial.NO_TOOLS, HostSettlement.SETTLED);
        }
        Listing control = ToolSession.listOnce(primarySessions, hostBaseRequestResponse, http, log);
        if (control.failed()) {
            return stop(hostBaseRequestResponse, control);
        }
        Set<ToolField> unstable = baseline.tools().unstableAgainst(control.tools());
        List<AuditIssue> found = new ArrayList<>();
        int listed = 0;
        for (Principal user : compared()) {
            Map<String, String> credentials = user.credentialHeaders().get();
            AuthStrategy auth = () -> credentials;
            Listing theirs = ToolSession.listOnce(userSessions.apply(auth), hostBaseRequestResponse, http, log);
            if (theirs.rateLimited()) {
                log.notRun(subject(hostBaseRequestResponse), SkipReason.rateLimited());
                return new HostTrialResult(found, HostSettlement.SETTLED);
            }
            if (theirs.failed()) {
                log.info("tools/list as " + user.name() + " got no answer");
                continue;
            }
            listed++;
            List<DefinitionChange> changes = baseline.tools().changesTo(theirs.tools(), unstable);
            log.info("decision: " + changes.size() + " tool definition field(s) differ for " + user.name()
                    + (unstable.isEmpty() ? "" : "; " + unstable.size() + " field(s) differed between the scanning "
                    + "user's sessions and were ignored"));
            if (!changes.isEmpty()) {
                List<HttpRequestResponse> evidence = Stream.of(baseline.firstExchange(), theirs.firstExchange())
                        .flatMap(Optional::stream).toList();
                found.add(issues.differsBetweenUsers(hostBaseRequestResponse.request().url(), user.name(), changes,
                        evidence, new HashSet<>(credentials.values())));
            }
        }
        if (listed == 0) {
            return stop(hostBaseRequestResponse, NO_COMPARED_LISTING, HostSettlement.INCONCLUSIVE);
        }
        return HostTrialResult.settled(found);
    }

    private List<Principal> compared() {
        PrincipalRoster roster = principals.get();
        return ComparedPrincipals.of(roster, roster.primary()).compared();
    }

    private HostTrialResult stop(HttpRequestResponse base, Listing failed) {
        return failed.rateLimited()
                ? stop(base, SkipReason.rateLimited(), HostSettlement.SETTLED)
                : stop(base, SessionDriftTrial.UNANSWERED, HostSettlement.INCONCLUSIVE);
    }

    private HostTrialResult stop(HttpRequestResponse base, SkipReason reason, HostSettlement settlement) {
        log.notRun(subject(base), reason);
        return new HostTrialResult(List.of(), settlement);
    }
}
