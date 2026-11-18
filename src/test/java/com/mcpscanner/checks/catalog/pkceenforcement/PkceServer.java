package com.mcpscanner.checks.catalog.pkceenforcement;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.shared.oauth.ScriptedHttp;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.json;
import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.queryParameter;
import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.redirect;

/** An authorization server that issues codes without a login, with switchable PKCE weaknesses. */
final class PkceServer {

    static final String ORIGIN = "https://mcp.example.com";
    static final String MCP = ORIGIN + "/mcp";
    static final String AUTHORIZE = ORIGIN + "/authorize";
    static final String REGISTER = ORIGIN + "/register";
    static final String TOKEN = ORIGIN + "/token";
    static final String REVOKE = ORIGIN + "/revoke";
    static final String CLIENT_URI = ORIGIN + "/register/probe-client";
    static final String ACCESS_TOKEN_PREFIX = "issued-access-token-";

    private final ScriptedHttp http = new ScriptedHttp();
    private final AtomicInteger issued = new AtomicInteger();
    private final Map<String, String[]> challenges = new ConcurrentHashMap<>();
    private String advertisedMethods = "[\"S256\"]";
    private boolean challengeOptional;
    private boolean verifierUnchecked;
    private boolean plainAccepted;
    private boolean loginRequired;

    PkceServer() {
        http.on("POST", REGISTER, request -> json(201, "{\"client_id\":\"probe-client\",\"redirect_uris\":"
                        + request.bodyToString().replaceAll(".*\"redirect_uris\":(\\[[^]]*]).*", "$1")
                        + ",\"registration_client_uri\":\"" + CLIENT_URI + "\",\"registration_access_token\":\"rat\"}"))
                .on("DELETE", CLIENT_URI, ScriptedHttp.status(204))
                .on("GET", AUTHORIZE, this::authorize)
                .on("POST", TOKEN, this::redeem)
                .on("POST", REVOKE, ScriptedHttp.status(200));
    }

    ScriptedHttp http() {
        return http.on("GET", ORIGIN + "/.well-known/oauth-authorization-server", json(200, "{\"issuer\":\"" + ORIGIN
                + "\",\"authorization_endpoint\":\"" + AUTHORIZE + "\",\"registration_endpoint\":\"" + REGISTER
                + "\",\"token_endpoint\":\"" + TOKEN + "\",\"revocation_endpoint\":\"" + REVOKE + "\""
                + (advertisedMethods == null ? "" : ",\"code_challenge_methods_supported\":" + advertisedMethods)
                + "}"));
    }

    PkceServer advertising(String methodsJson) {
        this.advertisedMethods = methodsJson;
        return this;
    }

    PkceServer challengeOptional() {
        this.challengeOptional = true;
        return this;
    }

    PkceServer verifierUnchecked() {
        this.verifierUnchecked = true;
        return this;
    }

    PkceServer plainAccepted() {
        this.plainAccepted = true;
        return this;
    }

    PkceServer loginRequired() {
        this.loginRequired = true;
        return this;
    }

    private String authorize(HttpRequest request) {
        if (loginRequired) {
            return ScriptedHttp.html("<form action=\"/login\"><input name=\"password\"></form>");
        }
        String callback = queryParameter(request, "redirect_uri");
        String state = queryParameter(request, "state");
        String challenge = queryParameter(request, "code_challenge");
        String method = queryParameter(request, "code_challenge_method");
        boolean accepted = challenge == null ? challengeOptional
                : "S256".equals(method) || ("plain".equals(method) && plainAccepted);
        if (!accepted) {
            return redirect(callback + "?error=invalid_request&state=" + state);
        }
        String code = "code-" + issued.incrementAndGet();
        challenges.put(code, new String[] {challenge, method});
        return redirect(callback + "?code=" + code + "&state=" + state);
    }

    private String redeem(HttpRequest request) {
        Map<String, String> form = form(request.bodyToString());
        String[] challenge = challenges.remove(form.getOrDefault("code", ""));
        if (challenge == null || !verifierMatches(challenge[0], challenge[1], form.get("code_verifier"))) {
            return json(400, "{\"error\":\"invalid_grant\"}");
        }
        return json(200, "{\"access_token\":\"" + ACCESS_TOKEN_PREFIX + issued.get()
                + "\",\"token_type\":\"Bearer\"}");
    }

    private boolean verifierMatches(String challenge, String method, String verifier) {
        if (challenge == null || verifierUnchecked) {
            return true;
        }
        if (verifier == null) {
            return false;
        }
        return "plain".equals(method) ? challenge.equals(verifier) : challenge.equals(s256(verifier));
    }

    List<String> sentTo(String url) {
        return http.sentTo(url).stream().map(HttpRequest::bodyToString).toList();
    }

    private static Map<String, String> form(String body) {
        return Arrays.stream(body.split("&")).map(pair -> pair.split("=", 2)).filter(pair -> pair.length == 2)
                .collect(Collectors.toMap(pair -> pair[0],
                        pair -> URLDecoder.decode(pair[1], StandardCharsets.UTF_8), (first, second) -> second));
    }

    private static String s256(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
