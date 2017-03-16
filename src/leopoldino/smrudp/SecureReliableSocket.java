package leopoldino.smrudp;

import leopoldino.smrudp.impl.NioUdpTransport;
import net.rudp.ReliableSocket;
import net.rudp.ReliableSocketProfile;
import net.rudp.impl.SYNSegment;
import net.rudp.impl.Segment;
import org.bouncycastle.crypto.tls.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.security.SecureRandom;

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
    protected NioUdpTransport _transport;
    protected DTLSTransport _secureTransport;
    protected TlsClient _client;
    protected SecureRandom _secureRandom;
    protected SecureScheduler _secureScheduler;

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
        super(channel, profile, SecureScheduler.getSecureScheduler());
        initClient(client, new SecureRandom());
    }

    protected SecureReliableSocket(DatagramChannel channel, ReliableSocketProfile profile, SocketAddress endpoint, TlsClient client) throws IOException {
        this(channel, profile, endpoint, client, new SecureRandom());
    }

    protected SecureReliableSocket(DatagramChannel channel, ReliableSocketProfile profile, SocketAddress endpoint, TlsClient client, SecureRandom secureRandom) throws IOException {
        super(channel, profile, SecureScheduler.getSecureScheduler());
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
        super(channel, profile, null, SecureScheduler.getSecureScheduler());
        initServer(server, new SecureRandom());
    }

    protected SecureReliableSocket(DatagramChannel channel, ReliableSocketProfile profile, SocketAddress bindAddress, TlsServer server) throws IOException {
        this(channel, profile, bindAddress, server, new SecureRandom());
    }

    protected SecureReliableSocket(DatagramChannel channel, ReliableSocketProfile profile, SocketAddress bindAddress, TlsServer server, SecureRandom secureRandom) throws IOException {
        super(channel, profile, bindAddress, SecureScheduler.getSecureScheduler());
        initServer(server, secureRandom);
    }

    public SecureReliableSocket(DatagramChannel channel, NioUdpTransport transport, DTLSTransport secureTransport, SocketAddress endpoint, ReliableSocketProfile profile) {
        super(channel, profile, SecureScheduler.getSecureScheduler());
        this._transport = transport;
        this._secureTransport = secureTransport;
        _endpoint = endpoint;
        init(null);
    }

    private void initClient(TlsClient client, SecureRandom secureRandom) {
        _client = client;
        init(secureRandom);
    }

    private void initServer(TlsServer server, SecureRandom secureRandom) throws IOException {
        init(secureRandom);
        _transport = new NioUdpTransport(_channel, getReceiveBufferSize(), getSendBufferSize());
        DTLSServerProtocol serverProtocol = new DTLSServerProtocol(secureRandom);
        _secureTransport = serverProtocol.accept(server, _transport);
        _endpoint = _transport.getEndpoint();
        super.connect(_endpoint, 0);
    }

    private void init(SecureRandom secureRandom) {
        _secureRandom = secureRandom;
        _secureScheduler = (SecureScheduler) _scheduler;
    }

    @Override
    public void connect(SocketAddress endpoint) throws IOException {
        connect(endpoint, 0);
    }

    @Override
    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        SYNSegment syn = new SYNSegment(100, _profile.maxOutstandingSegs(), _profile.maxSegmentSize(),
                _profile.retransmissionTimeout(), _profile.cumulativeAckTimeout(), _profile.nullSegmentTimeout(), _profile.maxRetrans(),
                _profile.maxCumulativeAcks(), _profile.maxOutOfSequence(), _profile.maxAutoReset());
        _channel.send(ByteBuffer.wrap(syn.getBytes()), endpoint);
        DTLSClientProtocol clientProtocol = new DTLSClientProtocol(_secureRandom);
        _transport = new NioUdpTransport(_channel, getReceiveBufferSize(), getSendBufferSize(), endpoint);
        _secureTransport = clientProtocol.connect(_client, _transport);
        super.connect(endpoint, timeout);
    }

    @Override
    protected void closeSocket() {
        try {
            _secureTransport.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        super.closeSocket();
    }

    @Override
    protected SelectionKey register() {
        return _secureScheduler.register(_channel, this, _secureTransport);
    }

    @Override
    protected void submitSegment(Segment segment) {
        _secureScheduler.submit(_secureTransport, segment);
    }

    protected void setEndpoint(SocketAddress endpoint) {
        _transport.setEndpoint(endpoint);
        _endpoint = endpoint;
    }
}
