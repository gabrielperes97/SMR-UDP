package leopoldino.smrudp;

import org.bouncycastle.crypto.tls.DatagramTransport;

import java.io.IOException;

/**
 * Use this only for tests. This transport show all data passing through it.
 */
public class TransparentTransport implements DatagramTransport {

    private static String digits = "0123456789abcdef";
    private DatagramTransport transport;

    public TransparentTransport(DatagramTransport transport) {
        this.transport = transport;
    }

    public static String toHex(byte[] data, int offset, int length) {
        StringBuffer buf = new StringBuffer();

        for (int i = offset; i != length; i++) {
            int v = data[i] & 0xff;

            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }

        return buf.toString();
    }

    @Override
    public int getReceiveLimit() throws IOException {
        return transport.getReceiveLimit();
    }

    @Override
    public int getSendLimit() throws IOException {
        return transport.getSendLimit();
    }

    @Override
    public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException {
        int length = transport.receive(buf, off, len, waitMillis);
        System.out.println("Brute receive: " + toHex(buf, off, length));
        return length;
    }

    @Override
    public void send(byte[] buf, int off, int len) throws IOException {
        System.out.println("Brute send: " + toHex(buf, off, len));
        transport.send(buf, off, len);
    }

    @Override
    public void close() throws IOException {
        transport.close();
    }
}
