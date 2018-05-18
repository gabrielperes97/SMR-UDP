package leopoldino.smrudp.MultipleClients;

import leopoldino.smrudp.DtlsClient;
import leopoldino.smrudp.SecureReliableSocket;
import leopoldino.smrudp.SecurityProfile;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Scanner;

/**
 * This test is an echo client. The client will be connected in the server and will reply with the same string on any
 * server.
 *
 * @author Gabriel Leopoldino
 */

public class Client {

    public static void main(String args[]) throws IOException, InterruptedException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, KeyManagementException {

        KeyStore ks = SecurityProfile.loadKeyStoreFromFile("foobar", "foobar");
        SecureReliableSocket reliableSocket = new SecureReliableSocket("127.0.0.1", ThreadedServer.PORT, SecurityProfile.getInstance(ks , "foobar"));
        System.out.println("Connected to " + reliableSocket.getRemoteSocketAddress());

        Scanner s = new Scanner(System.in);
        PrintStream out = new PrintStream(reliableSocket.getOutputStream());
        BufferedReader in = new BufferedReader(new InputStreamReader(reliableSocket.getInputStream()));
        while (true) {
            String msg = s.nextLine();
            out.println(msg);
            out.flush();
            if (msg.length() == 0)
                break;
            System.out.println(in.readLine());
        }

        reliableSocket.close();
    }
}