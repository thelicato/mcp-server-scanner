package com.mcpscanner.checks.catalog.prototypepollution;

import com.mcpscanner.checks.api.CheckFactory;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;

public final class PrototypePollutionCheckFactory implements CheckFactory {

    @Override
    public McpCheck create(CheckServices services) {
        return new PrototypePollutionCheck(services.burpNativeFields(), services.eventLog(), services.outsideBurp());
    }
}
