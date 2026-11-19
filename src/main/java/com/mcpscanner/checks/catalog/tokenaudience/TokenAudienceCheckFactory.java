package com.mcpscanner.checks.catalog.tokenaudience;

import com.mcpscanner.checks.api.CheckFactory;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;

public final class TokenAudienceCheckFactory implements CheckFactory {

    @Override
    public McpCheck create(CheckServices services) {
        return new TokenAudienceCheck(services.authStrategy(), services.eventLog());
    }
}
