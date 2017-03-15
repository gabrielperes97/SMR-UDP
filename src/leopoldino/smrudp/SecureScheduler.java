package leopoldino.smrudp;

import net.rudp.impl.Segment;
import org.bouncycastle.crypto.tls.DTLSTransport;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

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
    private ExecutorService _recvThreadPool;
    private Thread _rcvThread;

    public SecureScheduler() {
        _buffer = new byte[65535];
        _recvThreadPool = new ThreadPoolExecutor(16, 16, 0, TimeUnit.MILLISECONDS, new LinkedBlockingQueue<Runnable>(), new ScheduleFactory("Receive-Scheduler"));
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
        while (true) {
            if (_secureTransport != null) {
                try {
                    length = _secureTransport.receive(_buffer, 0, _buffer.length, 0);
                    segment = Segment.parse(_buffer, 0, length);
                    _recvThreadPool.submit(new ReceiveTask(segment));
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * Routine class to dispatch the Selector's received packages.
     */
    protected class ReceiveTask implements Runnable {
        private Segment segment;

        public ReceiveTask(Segment segment) {
            this.segment = segment;
        }

        @Override
        public void run() {
            _socket.scheduleReceive(segment);
        }
    }
}
