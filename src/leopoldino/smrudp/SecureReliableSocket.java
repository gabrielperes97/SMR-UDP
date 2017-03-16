package leopoldino.smrudp;

import net.rudp.ReliableSocket;
import net.rudp.ReliableSocketProfile;
import net.rudp.impl.SYNSegment;
import net.rudp.impl.Segment;
import org.bouncycastle.crypto.tls.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.security.SecureRandom;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Logger;

/**
 * This class implements a Secure Socket using a Reliable Socket. It's use the
 * Bouncy Castle DTLS implementation. To use, implement a TlsClient/TlsServer object, in the
 * tests we have an example about how to implement this.
 * <p>
 * We have two modes of use this, like a server or like a client. In a server mode the socket will behave like
 * a one-to-one server. In a client mode, the socket will behave like a classic client socket, connecting on
 * a server as configured.
 *
 * @author Gabriel Leopoldino
 */
public class SecureReliableSocket extends ReliableSocket {
    protected NioTransport _transport;
    protected DTLSTransport _secureTransport;
    protected TlsClient _client;
    protected SecureRandom _secureRandom;
    protected SecureScheduler _secureScheduler;
    protected NioScheduler _nioScheduler;
    protected SocketAddress _lastEndpoint;
    protected SelectionKey _nioKey;
    private BlockingQueue<byte[]> _rcvQueue;
    private int _sendBufferSize;
    private int _recvBufferSize;
    private Logger LOGGER = Logger.getLogger(SecureReliableSocket.class.getCanonicalName());

    public SecureReliableSocket(TlsClient client) throws IOException {
        this(new ReliableSocketProfile(), client);
    }

    public SecureReliableSocket(ReliableSocketProfile profile, TlsClient client) throws IOException {
        this(DatagramChannel.open(), profile, client);
    }

    public SecureReliableSocket(String host, int port, TlsClient client) throws IOException {
        this(DatagramChannel.open(), new ReliableSocketProfile(), new InetSocketAddress(host, port), client);
    }

    protected SecureReliableSocket(DatagramChannel channel, TlsClient client) {
        this(channel, new ReliableSocketProfile(), client);
    }

    protected SecureReliableSocket(DatagramChannel channel, ReliableSocketProfile profile, TlsClient client) {
        super(channel, profile, new SecureScheduler());
        initClient(client, new SecureRandom());
    }

    protected SecureReliableSocket(DatagramChannel channel, ReliableSocketProfile profile, SocketAddress endpoint, TlsClient client) throws IOException {
        this(channel, profile, endpoint, client, new SecureRandom());
    }

    protected SecureReliableSocket(DatagramChannel channel, ReliableSocketProfile profile, SocketAddress endpoint, TlsClient client, SecureRandom secureRandom) throws IOException {
        super(channel, profile, new SecureScheduler());
        initClient(client, secureRandom);
        connect(endpoint);
    }

    public SecureReliableSocket(TlsServer server) throws IOException {
        this(new ReliableSocketProfile(), server);
    }

    public SecureReliableSocket(ReliableSocketProfile profile, TlsServer server) throws IOException {
        this(DatagramChannel.open(), profile, server);
    }

    public SecureReliableSocket(int port, TlsServer server) throws IOException {
        this(DatagramChannel.open(), new ReliableSocketProfile(), new InetSocketAddress(port), server);
    }

    protected SecureReliableSocket(DatagramChannel channel, TlsServer server) throws IOException {
        this(channel, new ReliableSocketProfile(), server);
    }

    protected SecureReliableSocket(DatagramChannel channel, ReliableSocketProfile profile, TlsServer server) throws IOException {
        super(channel, profile, null, new SecureScheduler());
        initServer(server, new SecureRandom());
    }

    protected SecureReliableSocket(DatagramChannel channel, ReliableSocketProfile profile, SocketAddress bindAddress, TlsServer server) throws IOException {
        this(channel, profile, bindAddress, server, new SecureRandom());
    }

    protected SecureReliableSocket(DatagramChannel channel, ReliableSocketProfile profile, SocketAddress bindAddress, TlsServer server, SecureRandom secureRandom) throws IOException {
        super(channel, profile, bindAddress, new SecureScheduler());
        initServer(server, secureRandom);
    }

    public SecureReliableSocket(DatagramChannel channel, DTLSTransport secureTransport, SocketAddress endpoint, ReliableSocketProfile profile) {
        super(channel, profile, new SecureScheduler());
        this._secureTransport = secureTransport;
        _endpoint = endpoint;
        //init(null);
        //_secureScheduler = (SecureScheduler) _scheduler;
        //_secureScheduler.start(_secureTransport, this);
    }

    private void initClient(TlsClient client, SecureRandom secureRandom) {
        _client = client;
        init(secureRandom);
    }

    private void initServer(TlsServer server, SecureRandom secureRandom) throws IOException {
        init(secureRandom);
        DTLSServerProtocol serverProtocol = new DTLSServerProtocol(secureRandom);
        _secureTransport = serverProtocol.accept(server, _transport);
        super.connect(_endpoint, 0);
    }

    private void init(SecureRandom secureRandom) {
        _secureRandom = secureRandom;
        _sendBufferSize = (_profile.maxSegmentSize() - Segment.RUDP_HEADER_LEN) * _profile.maxRecvQueueSize();
        _recvBufferSize = (_profile.maxSegmentSize() - Segment.RUDP_HEADER_LEN) * _profile.maxSendQueueSize();
        _transport = new NioTransport();
        _secureScheduler = (SecureScheduler) _scheduler;
        _nioScheduler = NioScheduler.getNioScheduler();
        _nioKey = _nioScheduler.register(_channel, this);
        _rcvQueue = new LinkedBlockingQueue<>();
    }

    @Override
    public void connect(SocketAddress endpoint) throws IOException {
        connect(endpoint, 0);
    }

    @Override
    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        _endpoint = endpoint;
        SYNSegment syn = new SYNSegment(100, _profile.maxOutstandingSegs(), _profile.maxSegmentSize(),
                _profile.retransmissionTimeout(), _profile.cumulativeAckTimeout(), _profile.nullSegmentTimeout(), _profile.maxRetrans(),
                _profile.maxCumulativeAcks(), _profile.maxOutOfSequence(), _profile.maxAutoReset());
        byte[] synBytes = syn.getBytes();
        _nioScheduler.submit(_channel, endpoint, synBytes, 0, synBytes.length);
        DTLSClientProtocol clientProtocol = new DTLSClientProtocol(_secureRandom);
        _secureTransport = clientProtocol.connect(_client, _transport);
        super.connect(endpoint, timeout);
    }

    @Override
    protected void closeSocket() {
        _secureScheduler.close();
        try {
            _secureTransport.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        super.closeSocket();
    }

    @Override
    protected SelectionKey register() {
        _secureScheduler.start(_secureTransport, this);
        return _nioKey;
    }

    @Override
    protected void scheduleReceive(Segment segment) {
        super.scheduleReceive(segment);
    }

    @Override
    protected void submitSegment(Segment segment) {
        byte[] segBytes = segment.getBytes();
        try {
            _secureTransport.send(segBytes, 0, segBytes.length);
        } catch (IOException e) {
            LOGGER.warning("Error on submit segment");
            e.printStackTrace();
        }
    }

    protected void setEndpoint(SocketAddress endpoint) {
        _endpoint = endpoint;
    }

    protected void receiveRawData(byte[] buffer, int offset, int length) {
        try {
            _rcvQueue.put(buffer);
        } catch (InterruptedException e) {
            e.printStackTrace();
            LOGGER.warning("Sync error on receive data");
        }
        if (_endpoint == null) {
            _endpoint = _lastEndpoint;
        }
    }

    protected class NioTransport implements DatagramTransport {
        @Override
        public int getReceiveLimit() throws IOException {
            return _recvBufferSize;
        }

        @Override
        public int getSendLimit() throws IOException {
            return _sendBufferSize;
        }

        @Override
        public int receive(byte[] bytes, int i, int i1, int i2) throws IOException {
            byte[] buff = new byte[0];
            try {
                buff = _rcvQueue.take();
                System.arraycopy(buff, 0, bytes, i, buff.length);
            } catch (InterruptedException e) {
                e.printStackTrace();
                LOGGER.warning("Sync error on receive data");
            } finally {
                return buff.length;
            }
        }

        @Override
        public void send(byte[] bytes, int i, int i1) throws IOException {
            _nioScheduler.submit(_channel, _endpoint, bytes, i, i1);
        }

        @Override
        public void close() throws IOException {
        }
    }
}


