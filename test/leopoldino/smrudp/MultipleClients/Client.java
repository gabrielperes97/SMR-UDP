package leopoldino.smrudp.MultipleClients;

import leopoldino.smrudp.DtlsClient;
import leopoldino.smrudp.SecureReliableSocket;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;

/**
 * This test is an echo client. The client will be connected in the server and will reply with the same string on any
 * server.
 *
 * @author Gabriel Leopoldino
 */

public class Client {

    public static void main(String args[]) throws IOException, InterruptedException {
        SecureReliableSocket reliableSocket = new SecureReliableSocket("127.0.0.1", ThreadedServer.PORT, new DtlsClient());
        System.out.println("Connected to " + reliableSocket.getRemoteSocketAddress());

        PrintStream out = new PrintStream(reliableSocket.getOutputStream());
        BufferedReader in = new BufferedReader(new InputStreamReader(reliableSocket.getInputStream()));

        while (true) {
            String message = in.readLine();
            if (message != null) {
                /*break;*/
                System.out.println(message);
                out.println(message);
                out.flush();
            }

        }

        //reliableSocket.close();
    }
}