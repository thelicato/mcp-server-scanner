package com.mcpscanner.checks.catalog.pkceenforcement;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.api.OAuthSkipLog;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.catalog.pkceenforcement.Authorizer.Attempt;
import com.mcpscanner.checks.catalog.pkceenforcement.Redeemer.Redemption;
import com.mcpscanner.checks.shared.oauth.AuthorizationServer;
import com.mcpscanner.checks.shared.oauth.Pkce;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Requests codes with each PKCE weakness and reports the ones the token endpoint redeems. */
final class PkceAudit {

    private final AuthorizationServer server;
    private final Authorizer authorizer;
    private final Redeemer redeemer;
    private final OAuthSkipLog skips;
    private final String codeTests;

    PkceAudit(AuthorizationServer server, Authorizer authorizer, Redeemer redeemer, OAuthSkipLog skips,
              String mcpEndpoint) {
        this.server = server;
        this.authorizer = authorizer;
        this.redeemer = redeemer;
        this.skips = skips;
        this.codeTests = "the PKCE code tests for " + mcpEndpoint;
    }

    List<PkceFinding> run(ProbeClient client, Optional<PkceMetadata> metadata) {
        Attempt withoutChallenge = authorizer.authorize(client, Challenge.NONE);
        if (!withoutChallenge.reachedCallback()) {
            skips.notRun(codeTests, noCallbackReason(withoutChallenge));
            return List.of();
        }
        List<PkceFinding> findings = new ArrayList<>();
        redeemed(client, withoutChallenge, Optional.empty(), "no code_verifier",
                FindingKind.CHALLENGE_NOT_REQUIRED).ifPresent(findings::add);
        Attempt s256 = authorizer.authorize(client, Challenge.S256);
        redeemed(client, s256, Optional.of(Pkce.generate().verifier()), "a code_verifier that does not match the "
                + "challenge", FindingKind.VERIFIER_NOT_CHECKED).ifPresent(findings::add);
        if (metadata.map(advertised -> !advertised.advertises("plain")).orElse(true)) {
            Attempt plain = authorizer.authorize(client, Challenge.PLAIN);
            redeemed(client, plain, Optional.of(plain.pkce().verifier()), "the plain code_verifier",
                    FindingKind.PLAIN_ACCEPTED).ifPresent(findings::add);
        }
        return findings;
    }

    private Optional<PkceFinding> redeemed(ProbeClient client, Attempt attempt, Optional<String> verifier,
                                           String verifierDescription, FindingKind kind) {
        if (attempt.code().isEmpty()) {
            return Optional.empty();
        }
        Redemption redemption = redeemer.redeem(client, attempt.code().get(), verifier);
        if (redemption.accessToken().isEmpty()) {
            return Optional.empty();
        }
        List<HttpRequestResponse> evidence = new ArrayList<>(attempt.exchanges());
        redemption.exchange().ifPresent(evidence::add);
        List<String> facts = List.of(
                "Authorization request with " + attempt.challenge().description() + ": a code was issued",
                "Token request with " + verifierDescription + ": an access token was issued");
        return Optional.of(new PkceFinding(kind, server.authorizationEndpoint(), facts, evidence));
    }

    private static SkipReason noCallbackReason(Attempt attempt) {
        return attempt.hopLimitReached()
                ? SkipReason.budgetExhausted("the authorization redirects exceeded " + Authorizer.MAX_REDIRECTS
                        + " hops")
                : SkipReason.notApplicable("the authorization endpoint answered neither a code nor an error "
                        + "without a login, so no code can be obtained without a user");
    }
}
