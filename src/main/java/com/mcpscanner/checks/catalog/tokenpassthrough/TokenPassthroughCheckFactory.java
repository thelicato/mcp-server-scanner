package com.mcpscanner.checks.catalog.tokenpassthrough;

import com.mcpscanner.checks.api.CheckFactory;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;

public final class TokenPassthroughCheckFactory implements CheckFactory {

    @Override
    public McpCheck create(CheckServices services) {
        return new TokenPassthroughCheck(services.eventLog(), services.authStrategy(), services.collaboratorWatch(),
                services.lateIssues(), services.burpNativeFields());
    }
}
