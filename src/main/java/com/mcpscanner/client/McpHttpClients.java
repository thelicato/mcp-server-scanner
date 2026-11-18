package com.mcpscanner.client;

import com.mcpscanner.http.CertificateValidation;

import java.net.http.HttpClient;
import java.time.Duration;

public final class McpHttpClients {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);

    private McpHttpClients() {}

    public static HttpClient upstream(CertificateValidation certificates) {
        return certificates.httpClient()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(CONNECT_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }
}
