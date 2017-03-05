package leopoldino.smrudp.MultipleClients;

import leopoldino.smrudp.DtlsServer;
import leopoldino.smrudp.SecureReliableServerSocket;
import leopoldino.smrudp.SecureReliableSocket;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.util.Scanner;

/**
 * This test is a server of an echo client. The client will be connected in the server and will reply with the same string.
 * The SecureReliableServerSocket can support multiples clients.
 *
 * @author Gabriel Leopoldino
 */
public class ThreadedServer {

    public static final int PORT = 5510;

    public static void main(String[] args) throws IOException {
        SecureReliableServerSocket server = new SecureReliableServerSocket(PORT, new DtlsServer());
        SecureReliableSocket client = (SecureReliableSocket) server.accept();

        System.out.println("Conected to " + client.getRemoteSocketAddress());

        Scanner s = new Scanner(System.in);
        PrintStream out = new PrintStream(client.getOutputStream());
        BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
        while (true) {
            String msg = s.nextLine();
            out.println(msg);
            out.flush();
            if (msg.length() == 0)
                break;
            System.out.println(in.readLine());
        }
        client.close();
    }
}
