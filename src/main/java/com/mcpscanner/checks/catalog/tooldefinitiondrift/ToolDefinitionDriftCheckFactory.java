package com.mcpscanner.checks.catalog.tooldefinitiondrift;

import com.mcpscanner.checks.api.CheckFactory;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;

public final class ToolDefinitionDriftCheckFactory implements CheckFactory {

    @Override
    public McpCheck create(CheckServices services) {
        return new ToolDefinitionDriftCheck(services.eventLog(), services.authStrategy(), services.principals(),
                services.probeService(), services.outsideBurp());
    }
}
