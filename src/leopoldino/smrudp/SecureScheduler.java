package leopoldino.smrudp;

import net.rudp.impl.Segment;
import org.bouncycastle.crypto.tls.DTLSTransport;

import java.io.IOException;

/**
 * This is a improvised implementation of Input/output scheduler for SecureReliableSocket.
 * It works fine, but is not a perfect implementation, because of the limitations of DTLS
 * Bouncy Castle implementation (the lack of implementation with the NIO API).
 *
 * @author Gabriel Leopoldino
 */
public class SecureScheduler extends net.rudp.AsyncScheduler {

    private DTLSTransport _secureTransport;
    private SecureReliableSocket _socket;
    private byte[] _buffer;
    private Thread _rcvThread;

    public SecureScheduler() {
        _buffer = new byte[65535];
        _rcvThread = new Thread(this);
    }

    public void start(DTLSTransport secureTransport, SecureReliableSocket socket) {
        this._socket = socket;
        this._secureTransport = secureTransport;
        _rcvThread.start();
    }

    public void close() {
        this._rcvThread.interrupt();
    }

    @Override
    public void run() {
        // Declaring variables here to reuse.
        Segment segment;
        int length;

        // Scheduler Main Loop
        while (_secureTransport != null) { //TODO Repensar isso
            ///if (_secureTransport != null) {
                try {
                    length = _secureTransport.receive(_buffer, 0, _buffer.length, 0);
                    segment = Segment.parse(_buffer, 0, length);
                    _socket.scheduleReceive(segment);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            //}
        }
    }
}
