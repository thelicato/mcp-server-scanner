package com.mcpscanner.checks.catalog.unauthenticatedrequestexecution;

import com.mcpscanner.checks.api.CheckFactory;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;
import com.mcpscanner.checks.shared.session.OutsideBurpConnections;
import com.mcpscanner.checks.shared.session.ProbeSessions;
import com.mcpscanner.checks.shared.stream.FreshSessionStreams;

public final class UnauthenticatedRequestExecutionCheckFactory implements CheckFactory {

    @Override
    public McpCheck create(CheckServices services) {
        OutsideBurpConnections outsideBurp = services.outsideBurp();
        ProbeSessions probeSessions = new ProbeSessions(services.authStrategy(), outsideBurp);
        return new UnauthenticatedRequestExecutionCheck(services.eventLog(), services.authStrategy(), services.probeService(),
                new FreshSessionStreams(probeSessions, outsideBurp.streamOpener(services.eventLog())), outsideBurp);
    }
}
