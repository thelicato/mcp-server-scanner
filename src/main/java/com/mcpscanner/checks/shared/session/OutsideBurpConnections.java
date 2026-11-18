package com.mcpscanner.checks.shared.session;

import com.mcpscanner.checks.shared.stream.JdkStreamOpener;
import com.mcpscanner.checks.shared.stream.StreamOpener;
import com.mcpscanner.http.CertificateValidation;
import com.mcpscanner.logging.McpEventLog;

import java.time.Duration;
import java.util.Objects;

/** The connections a check opens itself, outside Burp, under the extension's certificate validation setting. */
public final class OutsideBurpConnections {

    private final CertificateValidation certificates;

    public OutsideBurpConnections(CertificateValidation certificates) {
        this.certificates = Objects.requireNonNull(certificates, "certificates");
    }

    public static OutsideBurpConnections validating() {
        return new OutsideBurpConnections(CertificateValidation.enforced());
    }

    public StreamingFallback streamingFallback() {
        return StreamingFallback.outsideBurp(certificates);
    }

    StreamingFallback streamingFallback(Duration responseTimeout) {
        return StreamingFallback.outsideBurp(responseTimeout, certificates);
    }

    public StreamOpener streamOpener(McpEventLog eventLog) {
        return new JdkStreamOpener(eventLog, certificates);
    }
}
