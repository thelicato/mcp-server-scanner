package com.mcpscanner.checks.catalog.tooldefinitiondrift;

import burp.api.montoya.http.HttpService;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.HostTrial;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.checks.api.RetryingHostCheck;
import com.mcpscanner.checks.shared.session.OutsideBurpConnections;
import com.mcpscanner.checks.shared.session.ProbeSessions;
import com.mcpscanner.logging.McpEventLog;

import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

public final class ToolDefinitionDriftCheck implements RetryingHostCheck {

    private final List<HostTrial> trials;

    public ToolDefinitionDriftCheck(McpEventLog eventLog, Supplier<AuthStrategy> authStrategy,
                                    Supplier<PrincipalRoster> principals,
                                    Supplier<Optional<HttpService>> sseProbeService,
                                    OutsideBurpConnections outsideBurp) {
        CheckLog log = new CheckLog(eventLog, ToolDefinitionDriftDescriptor.DESCRIPTOR.id());
        ToolDefinitionDriftIssues issues = new ToolDefinitionDriftIssues(ToolDefinitionDriftDescriptor.DESCRIPTOR);
        this.trials = List.of(
                new SessionDriftTrial(log, sseProbeService, new ProbeSessions(authStrategy, outsideBurp), issues),
                new UserDriftTrial(log, sseProbeService, principals, authStrategy, outsideBurp, issues));
    }

    @Override
    public CheckDescriptor descriptor() {
        return ToolDefinitionDriftDescriptor.DESCRIPTOR;
    }

    @Override
    public List<HostTrial> trials() {
        return trials;
    }
}
