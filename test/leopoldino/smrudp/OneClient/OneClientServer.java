package leopoldino.smrudp.OneClient;

import leopoldino.smrudp.DtlsServer;
import leopoldino.smrudp.MultipleClients.ThreadedServer;
import leopoldino.smrudp.SecureReliableSocket;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.util.Scanner;

/**
 * This test is a server of an echo client, but that is an one-to-one server. The client will be connected in the server
 * and will reply with the same string.
 * The SecureReliableSocket in server mode can support only one client.
 *
 * @author Gabriel Leopoldino
 */

public class OneClientServer {

    public static void main(String[] args) throws Exception {
        SecureReliableSocket socket = new SecureReliableSocket(ThreadedServer.PORT, new DtlsServer());
        System.out.println("Connected to " + socket.getRemoteSocketAddress());

        Scanner s = new Scanner(System.in);
        PrintStream out = new PrintStream(socket.getOutputStream());
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        while (true) {
            String msg = s.nextLine();
            out.println(msg);
            out.flush();
            if (msg.length() == 0)
                break;
            System.out.println(in.readLine());
        }
        socket.close();
    }
}
