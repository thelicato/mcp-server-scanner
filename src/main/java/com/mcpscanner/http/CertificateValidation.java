package com.mcpscanner.http;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.net.http.HttpClient;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import java.util.function.BooleanSupplier;

/**
 * The TLS trust of every connection the extension opens itself (outside Burp). The setting is read at each
 * handshake, so a change applies to the next connection without rebuilding any client. When validation is off,
 * any server certificate chain is accepted and its host name is not checked: the trust manager is an
 * {@link X509ExtendedTrustManager}, which is where JSSE runs endpoint identification.
 */
public final class CertificateValidation {

    private final SSLContext context;

    public CertificateValidation(BooleanSupplier enabled) {
        this(enabled, defaultTrustManager());
    }

    CertificateValidation(BooleanSupplier enabled, X509ExtendedTrustManager validating) {
        this.context = context(new SwitchableTrustManager(Objects.requireNonNull(enabled, "enabled"), validating));
    }

    public static CertificateValidation enforced() {
        return new CertificateValidation(() -> true);
    }

    public SSLContext sslContext() {
        return context;
    }

    public SSLSocketFactory socketFactory() {
        return context.getSocketFactory();
    }

    public HttpClient.Builder httpClient() {
        return HttpClient.newBuilder().sslContext(context);
    }

    /**
     * Drops the cached TLS sessions. A resumed session skips the trust manager, so without this a session
     * established while validation was off would be resumed unchecked after it is turned back on.
     */
    public void forgetSessions() {
        SSLSessionContext sessions = context.getClientSessionContext();
        Collections.list(sessions.getIds()).forEach(id -> {
            SSLSession session = sessions.getSession(id);
            if (session != null) {
                session.invalidate();
            }
        });
    }

    private static SSLContext context(TrustManager trust) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[] {trust}, null);
            return context;
        } catch (GeneralSecurityException unavailable) {
            throw new IllegalStateException("TLS is unavailable in this JVM", unavailable);
        }
    }

    private static X509ExtendedTrustManager defaultTrustManager() {
        try {
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init((KeyStore) null);
            return Arrays.stream(factory.getTrustManagers())
                    .filter(X509ExtendedTrustManager.class::isInstance)
                    .map(X509ExtendedTrustManager.class::cast)
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("The JVM has no X.509 trust manager"));
        } catch (GeneralSecurityException unavailable) {
            throw new IllegalStateException("The JVM's default trust store is unavailable", unavailable);
        }
    }

    private static final class SwitchableTrustManager extends X509ExtendedTrustManager {

        private final BooleanSupplier enabled;
        private final X509ExtendedTrustManager validating;

        private SwitchableTrustManager(BooleanSupplier enabled, X509ExtendedTrustManager validating) {
            this.enabled = enabled;
            this.validating = validating;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            if (enabled.getAsBoolean()) {
                validating.checkServerTrusted(chain, authType);
            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            if (enabled.getAsBoolean()) {
                validating.checkServerTrusted(chain, authType, socket);
            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            if (enabled.getAsBoolean()) {
                validating.checkServerTrusted(chain, authType, engine);
            }
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            validating.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            validating.checkClientTrusted(chain, authType, socket);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            validating.checkClientTrusted(chain, authType, engine);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return validating.getAcceptedIssuers();
        }
    }
}
