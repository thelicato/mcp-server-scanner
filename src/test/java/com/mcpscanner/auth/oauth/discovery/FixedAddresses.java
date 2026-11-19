package com.mcpscanner.auth.oauth.discovery;

import com.mcpscanner.auth.oauth.safety.DefaultSuspiciousDestinationGate;
import com.mcpscanner.auth.oauth.safety.HostResolver;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationConfirmer;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

final class FixedAddresses {

    static final HostResolver PUBLIC = host -> List.of(publicAddress(host));

    private FixedAddresses() {
    }

    static DefaultSuspiciousDestinationGate allowingSuspicious() {
        return DefaultSuspiciousDestinationGate.prompting(SuspiciousDestinationConfirmer.alwaysAllow(), PUBLIC, null);
    }

    private static InetAddress publicAddress(String host) {
        try {
            return InetAddress.getByAddress(host, new byte[] {93, (byte) 184, (byte) 215, 14});
        } catch (UnknownHostException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
