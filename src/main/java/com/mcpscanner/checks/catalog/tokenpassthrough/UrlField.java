package com.mcpscanner.checks.catalog.tokenpassthrough;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.checks.shared.field.InsertionPointNames;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/** An MCP field or header whose name or value says it takes a URL or host, and the probe value to put in it. */
record UrlField(String name, String probeValue) {

    private static final String HOST_SLOT = "{host}";
    private static final Pattern EXTENSION_FIELD = Pattern.compile("^MCP (?:field|header|template variable): ");
    private static final Pattern SCHEME_URL = Pattern.compile("^(https?)://\\S+$", Pattern.CASE_INSENSITIVE);
    private static final Pattern BARE_HOST = Pattern.compile(
            "^[a-z0-9-]+(?:\\.[a-z0-9-]+)+(?::\\d{1,5})?(?:/\\S*)?$", Pattern.CASE_INSENSITIVE);
    private static final Pattern WORD_BREAK = Pattern.compile("(?<=[a-z0-9])(?=[A-Z])|[^A-Za-z0-9]+");
    private static final Set<String> URL_WORDS = Set.of("url", "uri", "urls", "uris", "endpoint", "host", "hostname",
            "webhook", "callback", "href", "link", "server", "base", "api", "domain", "origin", "upstream", "proxy",
            "address");

    static Optional<UrlField> of(HttpRequest base, AuditInsertionPoint point, InsertionPointNames names) {
        String name = names.nameOf(base, point);
        if (!EXTENSION_FIELD.matcher(name).find()) {
            return Optional.empty();
        }
        String value = point.baseValue() == null ? "" : point.baseValue().trim();
        if (!takesUrl(leafOf(name), value)) {
            return Optional.empty();
        }
        return Optional.of(new UrlField(name, probeShape(value)));
    }

    String probe(String collaboratorHost) {
        return probeValue.replace(HOST_SLOT, collaboratorHost);
    }

    private static boolean takesUrl(String leaf, String value) {
        return SCHEME_URL.matcher(value).matches() || BARE_HOST.matcher(value).matches()
                || Arrays.stream(WORD_BREAK.split(leaf)).map(word -> word.toLowerCase(Locale.ROOT))
                        .anyMatch(word -> URL_WORDS.contains(word) || word.endsWith("url") || word.endsWith("uri"));
    }

    private static String probeShape(String value) {
        var scheme = SCHEME_URL.matcher(value);
        if (scheme.matches()) {
            return scheme.group(1).toLowerCase(Locale.ROOT) + "://" + HOST_SLOT + "/";
        }
        return BARE_HOST.matcher(value).matches() ? HOST_SLOT : "http://" + HOST_SLOT + "/";
    }

    private static String leafOf(String name) {
        String path = name.substring(name.indexOf(": ") + 2).replaceAll("\\[\\d+]", "");
        return path.substring(path.lastIndexOf('.') + 1);
    }
}
