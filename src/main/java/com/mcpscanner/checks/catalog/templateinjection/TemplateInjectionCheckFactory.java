package com.mcpscanner.checks.catalog.templateinjection;

import com.mcpscanner.checks.api.CheckFactory;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;

public final class TemplateInjectionCheckFactory implements CheckFactory {

    @Override
    public McpCheck create(CheckServices services) {
        return new TemplateInjectionCheck(services.burpNativeFields(), services.eventLog(), services.outsideBurp());
    }
}
