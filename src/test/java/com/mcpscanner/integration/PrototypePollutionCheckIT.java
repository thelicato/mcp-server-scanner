package com.mcpscanner.integration;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
class PrototypePollutionCheckIT {

    private static final String INVOICE = "{\"customer\":\"Ann\",\"options\":{\"currency\":\"GBP\"}}";

    @BeforeEach
    void installFactory() {
        MontoyaTestFactory.install();
    }

    @Test
    void reportsEveryArgumentObjectTheMergeFollowsProtoIn() throws Exception {
        List<AuditIssue> issues = InjectionTargets.scan("prototype-pollution", "prototype_pollution=vulnerable",
                "format_invoice", INVOICE);

        assertThat(issues).extracting(AuditIssue::name).containsOnly("MCP server-side prototype pollution");
        assertThat(issues).extracting(AuditIssue::detail)
                .anyMatch(detail -> detail.contains("params.arguments.customer"))
                .anyMatch(detail -> detail.contains("params.arguments.options.currency"))
                .allMatch(detail -> detail.contains("&quot;__proto__&quot;"));
    }

    @Test
    void staysSilentWhenTheMergeSkipsPrototypeKeys() throws Exception {
        assertThat(InjectionTargets.scan("prototype-pollution", "prototype_pollution=safe", "format_invoice",
                INVOICE)).isEmpty();
    }
}
