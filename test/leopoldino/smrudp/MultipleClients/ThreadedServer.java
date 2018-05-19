package leopoldino.smrudp.MultipleClients;

import leopoldino.smrudp.SecureReliableServerSocket;
import leopoldino.smrudp.SecureReliableSocket;
import leopoldino.smrudp.SecurityProfile;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * This test is a server of an echo client. The client will be connected in the server and will reply with the same string.
 * The SecureReliableServerSocket can support multiples clients.
 *
 * @author Gabriel Leopoldino
 */
public class ThreadedServer {

    public static final int PORT = 5510;

    public static void main(String[] args) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, KeyManagementException {
        KeyStore ks = SecurityProfile.loadKeyStoreFromFile("foobar", "foobar");
        SecureReliableServerSocket server = new SecureReliableServerSocket(PORT, SecurityProfile.getInstance(ks , "foobar"));
        SecureReliableSocket client = (SecureReliableSocket) server.accept();

        System.out.println("Conected to " + client.getRemoteSocketAddress());

        PrintStream out = new PrintStream(client.getOutputStream());
        BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));

        while (true) {
            String message = in.readLine();
            if (message == null)
                break;
            System.out.println(message);
            out.println(message);
            out.flush();

        }
        client.close();
    }
}
