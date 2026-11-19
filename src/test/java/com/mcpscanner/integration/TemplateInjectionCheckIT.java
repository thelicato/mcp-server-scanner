package com.mcpscanner.integration;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
class TemplateInjectionCheckIT {

    private static final String SIGNATURE = "{\"signature\":\"Ann Lee\"}";

    @BeforeEach
    void installFactory() {
        MontoyaTestFactory.install();
    }

    @Test
    void reportsJinjaTemplateSourceBuiltFromTheArgument() throws Exception {
        List<AuditIssue> issues = InjectionTargets.scan("template-injection", "template_injection=vulnerable",
                "preview_signature", SIGNATURE);

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP server-side template injection");
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("params.arguments.signature", "Jinja2");
        });
    }

    @Test
    void staysSilentWhenTheArgumentIsATemplateVariable() throws Exception {
        assertThat(InjectionTargets.scan("template-injection", "template_injection=safe", "preview_signature",
                SIGNATURE)).isEmpty();
    }
}
