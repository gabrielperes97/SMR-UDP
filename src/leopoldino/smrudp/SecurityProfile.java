package leopoldino.smrudp;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class SecurityProfile {

    private KeyManager keyManagers[];
    private TrustManager trustManagers[];
    private SSLContext context;

    public static KeyStore loadKeyStoreFromFile(String path, String password) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        return loadKeyStoreFromFile(path, password, "JKS");
    }

    public static KeyStore loadKeyStoreFromFile(String path, String password, String type) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance(type);
        keyStore.load(new FileInputStream(path), password.toCharArray());
        return keyStore;
    }

    public SecurityProfile(KeyManager[] keyManagers, TrustManager[] trustManagers, SecureRandom secureRandom) throws NoSuchAlgorithmException, KeyManagementException {
        this.keyManagers = keyManagers;
        this.trustManagers = trustManagers;
        this.context = SSLContext.getInstance("DTLSv1.2");

        this.context.init(keyManagers, trustManagers, secureRandom);
    }

    public SecurityProfile(KeyManager[] keyManagers, TrustManager[] trustManagers) throws NoSuchAlgorithmException, KeyManagementException {
        this(keyManagers, trustManagers, null);
    }

    public static SecurityProfile getInstance(KeyStore keyStore, String password) throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, KeyManagementException {
        return getInstance(keyStore, password, null);
    }

    public static SecurityProfile getInstance(KeyStore keyStore, String password, SecureRandom secureRandom) throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, KeyManagementException {
        KeyManagerFactory keyFact = KeyManagerFactory.getInstance("SunX509");
        keyFact.init(keyStore, password.toCharArray());

        TrustManagerFactory trustFact = TrustManagerFactory.getInstance("SunX509");
        trustFact.init(keyStore);

        return new SecurityProfile(keyFact.getKeyManagers(), trustFact.getTrustManagers(), secureRandom);
    }

    public SSLContext getContext() {
        return context;
    }
}
