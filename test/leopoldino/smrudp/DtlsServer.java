package leopoldino.smrudp;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.tls.*;

import java.io.IOException;

/**
 * Example server configuration, using DTLS 1.0 and server only authentication.
 * It is will load the server certificate chain and the minimum and prefered DTLS version.
 * The signer and encryption credentials are default.
 * This was taken from the Bouncy Castle Lightweight example codes.
 */
public class DtlsServer extends DefaultTlsServer {

    private AsymmetricKeyParameter privateKey;
    private Certificate certs;

    public DtlsServer() {
        try {
            String path = "sec-smrudp/";
            privateKey = TlsTestUtils.loadPrivateKeyResource(path + "certs/server-key.pem");
            certs = TlsTestUtils.loadCertificateChain(new String[]{path + "certs/server-cert.pem", path + "certs/ca-cert.pem"});

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    protected TlsEncryptionCredentials getRSAEncryptionCredentials() throws IOException {

        return new DefaultTlsEncryptionCredentials(context, certs, privateKey);
    }

    @Override
    protected TlsSignerCredentials getRSASignerCredentials() throws IOException {
        return new DefaultTlsSignerCredentials(context, certs, privateKey);
    }

    protected ProtocolVersion getMaximumVersion() {
        return ProtocolVersion.DTLSv10;
    }

    protected ProtocolVersion getMinimumVersion() {
        return ProtocolVersion.DTLSv10;
    }
}
