package com.mcpscanner.integration;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
class VerboseErrorsCheckIT {

    private static final String CONVERSION = "{\"celsius\":20,\"scale\":\"fahrenheit\"}";

    @BeforeEach
    void installFactory() {
        MontoyaTestFactory.install();
    }

    @Test
    void reportsTheTracebackOfAServerInDebugMode() throws Exception {
        List<AuditIssue> issues = InjectionTargets.scan("verbose-errors", "verbose_errors=vulnerable",
                "convert_temperature", CONVERSION);

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP verbose error messages");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
            assertThat(issue.detail()).contains("a stack trace", "verbose_errors.py", "Python 3.");
        });
    }

    @Test
    void staysSilentWhenErrorsAreShortAndFixed() throws Exception {
        assertThat(InjectionTargets.scan("verbose-errors", "verbose_errors=safe", "convert_temperature",
                CONVERSION)).isEmpty();
    }
}
