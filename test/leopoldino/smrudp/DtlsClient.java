package leopoldino.smrudp;

import org.bouncycastle.crypto.tls.*;

import java.io.IOException;

/**
 * Example client configuration, using DTLS 1.0 and server only authentication.
 * During the handshake the client will show the negociated DTLS version based on minimum and prefered client version
 * and the minimum version of the server, after will be showed a certificate chain fingerprint of the server.
 * This was taken from the Bouncy Castle Lightweight example codes.
 */
public class DtlsClient extends DefaultTlsClient {

    @Override
    public TlsAuthentication getAuthentication() throws IOException {
        return new ServerOnlyTlsAuthentication() {
            @Override
            public void notifyServerCertificate(Certificate certificate) throws IOException {
                org.bouncycastle.asn1.x509.Certificate[] chain = certificate.getCertificateList();
                System.out.println("TLS client received server certificate chain of length " + chain.length);
                for (int i = 0; i != chain.length; i++) {
                    org.bouncycastle.asn1.x509.Certificate entry = chain[i];
                    System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                            + entry.getSubject() + ")");
                }
            }
        };
    }

    public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException {
        super.notifyServerVersion(serverVersion);

        System.out.println("Negotiated " + serverVersion);
    }

    //Prefered version
    public ProtocolVersion getClientVersion() {
        return ProtocolVersion.DTLSv10;
    }

    public ProtocolVersion getMinimumVersion() {
        return ProtocolVersion.DTLSv10;
    }
}
