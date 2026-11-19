package com.mcpscanner.checks.catalog.tokenaudience;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.auth.grant.IssuedTokens;
import com.mcpscanner.auth.grant.LiveRefreshGrant;
import com.mcpscanner.auth.grant.RefreshGrant;
import com.mcpscanner.checks.catalog.tokenaudience.Refresher.Refresh;
import com.mcpscanner.checks.catalog.tokenaudience.TokenAcceptance.Judged;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/** Obtains a token for an unrelated resource from the live grant, restores the session, and judges the token. */
final class AudienceProbe {

    private final Refresher refresher;
    private final TokenAcceptance acceptance;

    AudienceProbe(Refresher refresher, TokenAcceptance acceptance) {
        this.refresher = refresher;
        this.acceptance = acceptance;
    }

    static URI foreignResource() {
        return URI.create("https://audience-probe-" + UUID.randomUUID().toString().substring(0, 8) + ".invalid/mcp");
    }

    Outcome run(LiveRefreshGrant live, URI foreign) {
        Set<String> secrets = new HashSet<>();
        RefreshGrant original = live.grant();
        record(original, secrets);
        acceptance.prime();
        Refresh foreignRefresh = refresher.refresh(original, Optional.of(foreign));
        if (foreignRefresh.tokens().isEmpty()) {
            return Outcome.refused(foreignRefresh.exchange(), secrets);
        }
        IssuedTokens issued = foreignRefresh.tokens().get();
        record(issued, secrets);
        live.adopt(issued);
        Refresh restore = refresher.refresh(live.grant(), original.resource());
        restore.tokens().ifPresent(tokens -> {
            record(tokens, secrets);
            live.adopt(tokens);
        });
        record(live.grant(), secrets);
        Optional<TokenAudience> audience = TokenAudience.of(issued.accessToken());
        if (audience.isPresent() && !audience.get().names(foreign)) {
            return Outcome.ignored(issued, foreignRefresh.exchange(), restore.tokens().isPresent(), audience.get(),
                    secrets);
        }
        Judged judged = acceptance.judge(issued.accessToken());
        return Outcome.judged(issued, foreignRefresh.exchange(), restore.tokens().isPresent(), audience, judged,
                secrets);
    }

    private static void record(RefreshGrant grant, Set<String> secrets) {
        secrets.add(grant.refreshToken());
        grant.client().secret().ifPresent(secrets::add);
    }

    private static void record(IssuedTokens tokens, Set<String> secrets) {
        secrets.add(tokens.accessToken());
        tokens.refreshToken().ifPresent(secrets::add);
    }

    record Outcome(Optional<IssuedTokens> issued, Optional<HttpRequestResponse> refresh, boolean restored,
                   Optional<TokenAudience> audience, Optional<Judged> judged, boolean resourceIgnored,
                   Set<String> secrets) {

        static Outcome refused(Optional<HttpRequestResponse> refresh, Set<String> secrets) {
            return new Outcome(Optional.empty(), refresh, true, Optional.empty(), Optional.empty(), false, secrets);
        }

        static Outcome ignored(IssuedTokens issued, Optional<HttpRequestResponse> refresh, boolean restored,
                               TokenAudience audience, Set<String> secrets) {
            return new Outcome(Optional.of(issued), refresh, restored, Optional.of(audience), Optional.empty(), true,
                    secrets);
        }

        static Outcome judged(IssuedTokens issued, Optional<HttpRequestResponse> refresh, boolean restored,
                              Optional<TokenAudience> audience, Judged judged, Set<String> secrets) {
            return new Outcome(Optional.of(issued), refresh, restored, audience, Optional.of(judged), false, secrets);
        }

        boolean accepted() {
            return judged.map(result -> result.verdict().isHit()).orElse(false);
        }

        List<HttpRequestResponse> evidence() {
            List<HttpRequestResponse> evidence = new ArrayList<>();
            refresh.ifPresent(evidence::add);
            judged.map(Judged::exchange).ifPresent(evidence::add);
            return evidence;
        }
    }
}
