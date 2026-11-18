package com.mcpscanner.checks.catalog.pkceenforcement;

import com.mcpscanner.checks.api.CheckFactory;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;

public final class PkceEnforcementCheckFactory implements CheckFactory {

    @Override
    public McpCheck create(CheckServices services) {
        return new PkceEnforcementCheck(services.eventLog());
    }
}
