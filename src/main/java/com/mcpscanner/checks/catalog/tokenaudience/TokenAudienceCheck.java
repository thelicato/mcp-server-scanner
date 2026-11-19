package com.mcpscanner.checks.catalog.tokenaudience;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.grant.RefreshGrant;
import com.mcpscanner.auth.grant.RefreshGrantStore;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.HostCheck;
import com.mcpscanner.checks.api.OAuthSkipLog;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.catalog.tokenaudience.AudienceProbe.Outcome;
import com.mcpscanner.checks.shared.oauth.IssuedToken;
import com.mcpscanner.checks.shared.oauth.OAuthHttp;
import com.mcpscanner.checks.shared.oauth.TokenRevocation;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.mcp.McpRequestKind;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

public final class TokenAudienceCheck implements HostCheck {

    private static final SkipReason NO_REFRESH_TOKEN =
            SkipReason.prerequisiteMissing("the OAuth session holds no refresh token");
    private static final SkipReason NO_LIVE_GRANT =
            SkipReason.prerequisiteMissing("the OAuth session holds no live refresh grant");

    private final Supplier<AuthStrategy> authStrategy;
    private final McpEventLog eventLog;
    private final CheckLog log;
    private final TokenAudienceIssues issues = new TokenAudienceIssues(TokenAudienceDescriptor.DESCRIPTOR);

    public TokenAudienceCheck(Supplier<AuthStrategy> authStrategy, McpEventLog eventLog) {
        this.authStrategy = authStrategy;
        this.eventLog = eventLog;
        this.log = new CheckLog(eventLog, TokenAudienceDescriptor.DESCRIPTOR.id());
    }

    @Override
    public CheckDescriptor descriptor() {
        return TokenAudienceDescriptor.DESCRIPTOR;
    }

    @Override
    public boolean appliesTo(HttpRequestResponse hostBaseRequestResponse) {
        return McpRequestDetector.classify(hostBaseRequestResponse) != McpRequestKind.NOT_MCP
                && authStrategy.get().refreshGrantStore().isPresent();
    }

    @Override
    public String appliesOnlyTo() {
        return "MCP requests while the OAuth session holds a refresh token";
    }

    @Override
    public List<AuditIssue> audit(HttpRequestResponse hostBaseRequestResponse, Http http) {
        String mcpEndpoint = hostBaseRequestResponse.request().url();
        Optional<RefreshGrantStore> store = authStrategy.get().refreshGrantStore();
        if (store.isEmpty()) {
            log.notRun(mcpEndpoint, NO_REFRESH_TOKEN);
            return List.of();
        }
        Optional<RefreshGrant> grant = store.get().withExclusiveGrant(live -> live.grant());
        if (grant.isEmpty()) {
            log.notRun(mcpEndpoint, NO_LIVE_GRANT);
            return List.of();
        }
        OAuthHttp oauthHttp = new OAuthHttp(http);
        OAuthSkipLog skips = new OAuthSkipLog(log, oauthHttp);
        Optional<TokenEndpoint> endpoint = TokenEndpoint.of(oauthHttp, grant.get().issuer());
        if (endpoint.isEmpty()) {
            skips.notRun(mcpEndpoint, SkipReason.prerequisiteMissing("no authorization server metadata naming "
                    + grant.get().issuer() + " with a token endpoint"));
            return List.of();
        }
        URI foreign = AudienceProbe.foreignResource();
        AudienceProbe probe = new AudienceProbe(new Refresher(oauthHttp, endpoint.get().token()),
                new TokenAcceptance(http, hostBaseRequestResponse.request(), authStrategy));
        Optional<Outcome> outcome = store.get().withExclusiveGrant(live -> probe.run(live, foreign));
        if (outcome.isEmpty()) {
            log.notRun(mcpEndpoint, NO_LIVE_GRANT);
            return List.of();
        }
        try {
            return judged(mcpEndpoint, foreign, outcome.get(), skips);
        } finally {
            skips.stoppedIfRateLimited(mcpEndpoint);
            cleanUp(outcome.get(), endpoint.get(), oauthHttp, grant.get().client().clientId());
        }
    }

    private List<AuditIssue> judged(String mcpEndpoint, URI foreign, Outcome outcome, OAuthSkipLog skips) {
        if (outcome.issued().isEmpty()) {
            skips.notRun(mcpEndpoint, SkipReason.notApplicable("the authorization server issued no token for "
                    + "another resource, which is correct"));
            return List.of();
        }
        if (outcome.resourceIgnored()) {
            skips.notRun(mcpEndpoint, SkipReason.notApplicable("the authorization server ignored the resource "
                    + "parameter and issued a token for " + outcome.audience().orElseThrow().audiences()));
            return List.of();
        }
        if (!outcome.accepted()) {
            log.info("the MCP server refused a token requested for " + foreign + " at " + mcpEndpoint);
            return List.of();
        }
        AuditIssue issue = issues.accepted(mcpEndpoint, foreign, outcome);
        log.info("reported " + issue.name() + " for " + mcpEndpoint);
        return List.of(issue);
    }

    private void cleanUp(Outcome outcome, TokenEndpoint endpoint, OAuthHttp http, String clientId) {
        if (!outcome.restored()) {
            log.warn("could not refresh the OAuth session back to this server after the audience probe; sign in "
                    + "again if requests start failing");
            return;
        }
        outcome.issued().ifPresent(issued -> new TokenRevocation(http, endpoint.revocation(), endpoint.token(),
                eventLog).revoke(clientId, List.of(IssuedToken.access(issued.accessToken()))));
    }
}
