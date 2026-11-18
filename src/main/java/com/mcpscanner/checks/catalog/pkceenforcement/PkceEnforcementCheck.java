package com.mcpscanner.checks.catalog.pkceenforcement;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.HostCheck;
import com.mcpscanner.checks.api.OAuthSkipLog;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.shared.oauth.AuthorizationServer;
import com.mcpscanner.checks.shared.oauth.AuthorizationServerDiscovery;
import com.mcpscanner.checks.shared.oauth.HttpUris;
import com.mcpscanner.checks.shared.oauth.IssuedToken;
import com.mcpscanner.checks.shared.oauth.OAuthHttp;
import com.mcpscanner.checks.shared.oauth.ProbeClientRegistrar;
import com.mcpscanner.checks.shared.oauth.TokenRevocation;
import com.mcpscanner.checks.shared.redaction.ExchangeRedactor;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.mcp.McpRequestKind;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public final class PkceEnforcementCheck implements HostCheck {

    private final CheckLog log;
    private final McpEventLog eventLog;
    private final PkceEnforcementIssues issues = new PkceEnforcementIssues(PkceEnforcementDescriptor.DESCRIPTOR);

    public PkceEnforcementCheck(McpEventLog eventLog) {
        this.log = new CheckLog(eventLog, PkceEnforcementDescriptor.DESCRIPTOR.id());
        this.eventLog = eventLog;
    }

    @Override
    public CheckDescriptor descriptor() {
        return PkceEnforcementDescriptor.DESCRIPTOR;
    }

    @Override
    public boolean appliesTo(HttpRequestResponse hostBaseRequestResponse) {
        return hostBaseRequestResponse.request() != null
                && McpRequestDetector.classify(hostBaseRequestResponse) != McpRequestKind.NOT_MCP
                && HttpUris.parse(hostBaseRequestResponse.request().url()).isPresent();
    }

    @Override
    public String appliesOnlyTo() {
        return "MCP requests to an http(s) URL";
    }

    @Override
    public List<AuditIssue> audit(HttpRequestResponse hostBaseRequestResponse, Http http) {
        OAuthHttp oauthHttp = new OAuthHttp(http);
        OAuthSkipLog skips = new OAuthSkipLog(log, oauthHttp);
        String mcpEndpoint = hostBaseRequestResponse.request().url();
        try {
            return audit(hostBaseRequestResponse, oauthHttp, skips, mcpEndpoint);
        } finally {
            skips.stoppedIfRateLimited(mcpEndpoint);
        }
    }

    private List<AuditIssue> audit(HttpRequestResponse base, OAuthHttp http, OAuthSkipLog skips, String mcpEndpoint) {
        Optional<AuthorizationServer> server = new AuthorizationServerDiscovery(http).discover(base);
        if (server.isEmpty()) {
            skips.notRun(mcpEndpoint, SkipReason.prerequisiteMissing("no OAuth authorization server discovered"));
            return List.of();
        }
        Optional<PkceMetadata> metadata = PkceMetadata.read(http, server.get().issuer());
        List<PkceFinding> findings = new ArrayList<>();
        metadata.filter(read -> !read.problems().isEmpty()).ifPresent(read -> findings.add(new PkceFinding(
                FindingKind.METADATA, server.get().issuer(), read.problems(), List.of(read.exchange()))));
        List<IssuedToken> tokens = new ArrayList<>();
        findings.addAll(codeFindings(server.get(), metadata, http, skips, mcpEndpoint, tokens));
        return issues.issues(findings, new ExchangeRedactor(tokens.stream().map(IssuedToken::value)
                .collect(Collectors.toSet())));
    }

    private List<PkceFinding> codeFindings(AuthorizationServer server, Optional<PkceMetadata> metadata, OAuthHttp http,
                                           OAuthSkipLog skips, String mcpEndpoint, List<IssuedToken> tokens) {
        String codeTests = "the PKCE code tests for " + mcpEndpoint;
        if (server.registrationEndpoint().isEmpty()) {
            skips.notRun(codeTests, SkipReason.prerequisiteMissing("the authorization server offers no dynamic "
                    + "client registration endpoint"));
            return List.of();
        }
        if (server.tokenEndpoint().isEmpty()) {
            skips.notRun(codeTests, SkipReason.prerequisiteMissing("the authorization server advertises no token "
                    + "endpoint"));
            return List.of();
        }
        ProbeClientRegistrar registrar = new ProbeClientRegistrar(http, server.registrationEndpoint().get());
        try {
            Optional<ProbeClient> client = ProbeClient.register(registrar);
            if (client.isEmpty()) {
                skips.notRun(codeTests,
                        SkipReason.prerequisiteMissing("dynamic client registration did not issue a client_id"));
                return List.of();
            }
            Redeemer redeemer = new Redeemer(http, server.tokenEndpoint().get(), server.resource());
            try {
                return new PkceAudit(server, new Authorizer(http, server), redeemer, skips, mcpEndpoint)
                        .run(client.get(), metadata);
            } finally {
                tokens.addAll(redeemer.issued());
                new TokenRevocation(http, server.revocationEndpoint(), server.tokenEndpoint().get(), eventLog)
                        .revoke(client.get().clientId(), redeemer.issued());
            }
        } finally {
            log.info(registrar.deleteRegisteredClients().summary() + " for " + mcpEndpoint);
        }
    }
}
