package com.mcpscanner.http;

import com.mcpscanner.http.wire.SocketHttpTransport;
import com.mcpscanner.http.wire.UnsentRequestException;
import com.mcpscanner.http.wire.WireExchange;
import com.mcpscanner.http.wire.WireRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.TestPki;
import com.sun.net.httpserver.HttpsServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLHandshakeException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificateValidationTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private static HttpsServer server;

    @BeforeAll
    static void startServerWithAnUntrustedCertificate(@TempDir Path directory) throws Exception {
        server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setHttpsConfigurator(TestPki.generate(directory).server());
        server.createContext("/", exchange -> {
            byte[] body = "ok".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Connection", "close");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
    }

    @AfterAll
    static void stopServer() {
        server.stop(0);
    }

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void enforcedValidationRefusesACertificateTheJdkDoesNotTrust() {
        HttpClient client = CertificateValidation.enforced().httpClient().connectTimeout(TIMEOUT).build();

        assertThatThrownBy(() -> client.send(get(), HttpResponse.BodyHandlers.ofString()))
                .isInstanceOf(SSLHandshakeException.class);
    }

    @Test
    void disabledValidationAcceptsAnyCertificate() throws Exception {
        HttpClient client = new CertificateValidation(() -> false).httpClient().connectTimeout(TIMEOUT).build();

        assertThat(client.send(get(), HttpResponse.BodyHandlers.ofString()).body()).isEqualTo("ok");
    }

    @Test
    void turningValidationBackOnRefusesTheNextConnectionInsteadOfResumingItsUncheckedSession() throws Exception {
        AtomicBoolean validate = new AtomicBoolean(false);
        CertificateValidation certificates = new CertificateValidation(validate::get);
        HttpClient client = certificates.httpClient().connectTimeout(TIMEOUT).build();
        assertThat(client.send(get(), HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(200);

        validate.set(true);
        certificates.forgetSessions();

        assertThatThrownBy(() -> client.send(get(), HttpResponse.BodyHandlers.ofString()))
                .isInstanceOf(SSLHandshakeException.class);
    }

    @Test
    void theRawSocketSenderFollowsTheSetting() throws Exception {
        AtomicBoolean validate = new AtomicBoolean(true);
        SocketHttpTransport transport = new SocketHttpTransport(TIMEOUT, new CertificateValidation(validate::get));

        assertThatThrownBy(() -> transport.exchange(wireGet())).isInstanceOf(UnsentRequestException.class);

        validate.set(false);
        try (WireExchange exchange = transport.exchange(wireGet())) {
            assertThat(exchange.response().status()).isEqualTo(200);
        }
    }

    private static HttpRequest get() {
        return HttpRequest.newBuilder(uri()).timeout(TIMEOUT).build();
    }

    private static WireRequest wireGet() {
        return WireRequest.of(burp.api.montoya.http.message.requests.HttpRequest.httpRequestFromUrl(uri().toString()));
    }

    private static URI uri() {
        return URI.create("https://127.0.0.1:" + server.getAddress().getPort() + "/");
    }
}
