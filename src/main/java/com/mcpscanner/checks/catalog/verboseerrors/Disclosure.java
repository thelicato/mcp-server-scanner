package com.mcpscanner.checks.catalog.verboseerrors;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

enum Disclosure {
    STACK_TRACE("a stack trace",
            "Traceback \\(most recent call last\\):",
            "File \"[^\"\\n]+\", line \\d+, in \\S+",
            "\\bat [\\w$]+(?:\\.[\\w$<>]+)+\\([\\w$]+\\.(?:java|kt|scala):\\d+\\)",
            "\\bat (?:[\\w$.<>\\[\\] ]+ )?\\(?(?:/|[A-Za-z]:\\\\|file://)[^()\\s]+\\.(?:js|mjs|cjs|ts):\\d+:\\d+\\)?",
            "goroutine \\d+ \\[[a-z ]+\\]:",
            "\\bat [\\w.`<>]+\\(.*\\) in .+:line \\d+",
            "from (?:/|[A-Za-z]:\\\\)\\S+\\.rb:\\d+:in",
            "Stack trace:\\s*#0 "),
    SOURCE_PATH("a server source file path",
            "(?<![\\w.:/\\\\-])(?:/(?:home|usr|var|opt|srv|app|root|Users|tmp|workspace)/|[A-Za-z]:\\\\)"
                    + "[^\\s\"'<>:]*?"
                    + "\\.(?:py|js|mjs|cjs|ts|java|kt|go|rb|php|cs)\\b",
            "[^\\s\"'<>]*(?:site-packages|node_modules)/[^\\s\"'<>:]+"),
    VERSION("a framework or runtime version",
            "\\b(?:Python|CPython|Node(?:\\.js)?|PHP|Ruby|OpenJDK|Werkzeug|Flask|Django|FastAPI|Starlette|uvicorn"
                    + "|gunicorn|Express|Spring Boot|Tomcat|Jetty|Kestrel|ASP\\.NET Core|pydantic)[/ ]v?\\d+\\.\\d+"
                    + "(?:\\.\\d+)?\\b",
            "errors\\.pydantic\\.dev/\\d+\\.\\d+");

    static final int SHOWN_CHARACTERS = 200;

    private final String described;
    private final List<Pattern> patterns;

    Disclosure(String described, String... patterns) {
        this.described = described;
        this.patterns = Arrays.stream(patterns).map(Pattern::compile).toList();
    }

    String described() {
        return described;
    }

    List<String> matchesIn(String text) {
        List<String> found = new ArrayList<>();
        for (Pattern pattern : patterns) {
            Matcher matcher = pattern.matcher(text);
            while (matcher.find()) {
                found.add(matcher.group());
            }
        }
        return found;
    }
}
