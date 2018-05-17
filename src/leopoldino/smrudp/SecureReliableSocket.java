package leopoldino.smrudp;

import net.rudp.ReliableSocket;
import net.rudp.ReliableSocketProfile;
import net.rudp.impl.SYNSegment;
import net.rudp.impl.Segment;

import javax.net.ssl.SSLEngine;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * This class implements a Secure Socket using a Reliable Socket. It's use the
 * Java Secure Socket Extension (JSSE). Working fine in non-blocking mode.
 * @author Gabriel Leopoldino
 */
public class SecureReliableSocket extends ReliableSocket {

    protected SecureScheduler secureScheduler;
    protected ByteBuffer outAppData;
    protected ByteBuffer outNetData;
    protected ByteBuffer inAppData;
    protected ByteBuffer inNetData;
    protected ReceiveThread receiveThread;

    protected SSLEngine sslEngine;

    //Raw data received from UDP
    protected ConcurrentLinkedQueue<ByteBuffer> receivedQueue;

    public SecureReliableSocket() throws IOException {
        this(new ReliableSocketProfile());
    }

    public SecureReliableSocket(ReliableSocketProfile profile) throws IOException {
        this(DatagramChannel.open(), profile);
    }

    public SecureReliableSocket(String host, int port) throws IOException {
        this(DatagramChannel.open(), new InetSocketAddress(host, port), new ReliableSocketProfile());
    }

    protected SecureReliableSocket(DatagramChannel channel) {
        this(channel, new ReliableSocketProfile());
    }

    protected SecureReliableSocket(DatagramChannel channel, ReliableSocketProfile profile) {
        super(channel, profile, SecureScheduler.getSecureScheduler());
        init();
    }

    public SecureReliableSocket(DatagramChannel channel, SocketAddress endpoint, ReliableSocketProfile profile) throws IOException {
        super(channel, profile, SecureScheduler.getSecureScheduler());
        init();
        connect(endpoint);
    }

    private void init() {
        secureScheduler = (SecureScheduler) _scheduler;
        this.receiveThread = new ReceiveThread();
        this.receivedQueue = new ConcurrentLinkedQueue<>();
    }

    @Override
    public void connect(SocketAddress endpoint) throws IOException {
        connect(endpoint, 0);
    }

    @Override
    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        /*SYNSegment syn = new SYNSegment(100, _profile.maxOutstandingSegs(), _profile.maxSegmentSize(),
                _profile.retransmissionTimeout(), _profile.cumulativeAckTimeout(), _profile.nullSegmentTimeout(), _profile.maxRetrans(),
                _profile.maxCumulativeAcks(), _profile.maxOutOfSequence(), _profile.maxAutoReset());
        this.submitSegment(syn);*/
        /*DTLSClientProtocol clientProtocol = new DTLSClientProtocol(_secureRandom);
        _transport = new NioUdpTransport(_channel, getReceiveBufferSize(), getSendBufferSize(), endpoint);
        _secureTransport = clientProtocol.connect(_client, _transport);*/

        this.receiveThread.start();
        super.connect(endpoint, timeout);
    }

    public void turnAServer()
    {

    }

    @Override
    protected void closeSocket() {
        super.closeSocket();
    }

    @Override
    protected SelectionKey register() {
        return this.secureScheduler.register(this._channel, this);
    }

    @Override
    protected void submitSegment(Segment segment) {
        this.secureScheduler.submit(this._channel, this._endpoint, ByteBuffer.wrap(segment.getBytes()));
    }


    protected void setEndpoint(SocketAddress endpoint) {
        _endpoint = endpoint;
    }

    public SSLEngine getSslEngine() {
        return sslEngine;
    }

    public int getNetBufferSize()
    {
        //return this.sslEngine.getSession().getPacketBufferSize();
        return 65535;
    }

    protected void receiveRawData(ByteBuffer data)
    {
        receivedQueue.offer(data);
    }

    private class ReceiveThread extends Thread
    {
        @Override
        public void run() {
            while(true)
            {
                ByteBuffer data = receivedQueue.poll();
                if (data != null)
                {
                    Segment segment = Segment.parse(data.array(), 0, data.position());
                    SecureReliableSocket.this.scheduleReceive(segment);
                }
            }
        }
    }
}
