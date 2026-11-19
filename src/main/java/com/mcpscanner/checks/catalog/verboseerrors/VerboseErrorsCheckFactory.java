package com.mcpscanner.checks.catalog.verboseerrors;

import com.mcpscanner.checks.api.CheckFactory;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;

public final class VerboseErrorsCheckFactory implements CheckFactory {

    @Override
    public McpCheck create(CheckServices services) {
        return new VerboseErrorsCheck(services.eventLog(), services.outsideBurp());
    }
}
