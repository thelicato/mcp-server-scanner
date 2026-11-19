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
class NosqlInjectionCheckIT {

    private static final String CHECK = "nosql-injection";
    private static final String ISSUE = "MCP NoSQL injection";

    @BeforeEach
    void installFactory() {
        MontoyaTestFactory.install();
    }

    @Test
    void reportsOperatorsPassedIntoAFilter() throws Exception {
        List<AuditIssue> issues = InjectionTargets.scan(CHECK, "nosql_operator_injection=vulnerable",
                "find_note_by_title", "{\"title\":\"standup\"}");

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(ISSUE);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("params.arguments.title", "$ne", "$regex");
        });
    }

    @Test
    void staysSilentWhenObjectsAreRefused() throws Exception {
        assertThat(InjectionTargets.scan(CHECK, "nosql_operator_injection=safe", "find_note_by_title",
                "{\"title\":\"standup\"}")).isEmpty();
    }

    @Test
    void reportsAWhereExpressionBuiltFromTheArgument() throws Exception {
        List<AuditIssue> issues = InjectionTargets.scan(CHECK, "nosql_where_injection=vulnerable",
                "list_notes_by_owner", "{\"owner\":\"alice\"}");

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("params.arguments.owner", "single-quoted $where");
        });
    }

    @Test
    void staysSilentWhenTheOwnerIsAnEqualityOperand() throws Exception {
        assertThat(InjectionTargets.scan(CHECK, "nosql_where_injection=safe", "list_notes_by_owner",
                "{\"owner\":\"alice\"}")).isEmpty();
    }
}
