package com.mcpscanner.checks.catalog.nosqlinjection;

import com.mcpscanner.checks.api.CheckFactory;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;

public final class NosqlInjectionCheckFactory implements CheckFactory {

    @Override
    public McpCheck create(CheckServices services) {
        return new NosqlInjectionCheck(services.burpNativeFields(), services.eventLog(), services.outsideBurp());
    }
}
