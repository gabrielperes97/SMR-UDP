package leopoldino.smrudp;

import net.rudp.*;
import net.rudp.impl.SYNSegment;
import net.rudp.impl.Segment;
import net.rudp.impl.UIDSegment;
import org.bouncycastle.crypto.tls.DTLSServerProtocol;
import org.bouncycastle.crypto.tls.DTLSTransport;
import org.bouncycastle.crypto.tls.DatagramTransport;
import org.bouncycastle.crypto.tls.TlsServer;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.BiConsumer;
import java.util.logging.Logger;

/**
 * This class implements a Secure Server Socket for a ReliableSocket. It is implemented using
 * Bouncy Castle DTLS implementation. To use, implement a TlsServer object, in the
 * tests we have an example about how to implement this.
 *
 * @author Gabriel Leopoldino
 */

public class SecureReliableServerSocket extends ReliableServerSocket {

    public static final Logger LOGGER = Logger.getLogger(SecureReliableServerSocket.class.getCanonicalName());
    static private ExecutorService _connectionPool;
    /* A table of active opened client sockets. */
    private final HashMap<SocketAddress, ClientHolder> _clientSockTable;
    private DTLSServerProtocol _dtlsProtocol;
    private TlsServer _serverConfig;
    private ReceiverThread _receiverThread;
    /* Consumer task for the received packets */
    private ProcessSegmentThread _processSegmentThread;
    private NioScheduler _scheduler;
    private int _sendBufferSize;
    private int _recvBufferSize;


    /* Buffer for the received packets used for the Producer/Consumer mechanism */
    private BlockingQueue<BufferedPacket> _recvRawPacketsBuffer;

    public SecureReliableServerSocket(TlsServer serverConfig) throws IOException {
        this(0, 0, null, new ReliableSocketProfile(), serverConfig, new SecureRandom());
    }

    public SecureReliableServerSocket(int port, TlsServer serverConfig) throws IOException {
        this(port, 0, null, new ReliableSocketProfile(), serverConfig, new SecureRandom());
    }

    public SecureReliableServerSocket(int port, ReliableSocketProfile profile, TlsServer serverConfig) throws IOException {
        this(port, 0, null, profile, serverConfig, new SecureRandom());
    }

    public SecureReliableServerSocket(int port, int backlog, TlsServer serverConfig) throws IOException {
        this(port, backlog, null, new ReliableSocketProfile(), serverConfig, new SecureRandom());
    }

    public SecureReliableServerSocket(int port, int backlog, InetAddress bindAddr, ReliableSocketProfile profile, TlsServer server, SecureRandom secureRandom) throws IOException {
        super(new InetSocketAddress(bindAddr, port), backlog, profile, null, new TreeMap<UUID, SocketAddress>());

        _stateListener = new StateListener();
        _clientSockTable = new HashMap<SocketAddress, ClientHolder>();

        _timeout = 0;
        _closed = false;

        if (_connectionPool == null) {
            _connectionPool = Executors.newFixedThreadPool(32, new AsyncScheduler.ScheduleFactory("In Connection"));
        }

        _sendBufferSize = (_profile.maxSegmentSize() - Segment.RUDP_HEADER_LEN) * _profile.maxRecvQueueSize();
        _recvBufferSize = (_profile.maxSegmentSize() - Segment.RUDP_HEADER_LEN) * _profile.maxSendQueueSize();
        _serverConfig = server;
        _dtlsProtocol = new DTLSServerProtocol(secureRandom);
        _scheduler = NioScheduler.getNioScheduler();

        _receiverThread = new ReceiverThread();
        _receiverThread.start();
    }

    @Override
    public Socket accept() throws IOException {
        if (isClosed()) {
            throw new SocketException("Socket is closed");
        }
        synchronized (_backlog) {
            while (_backlog.isEmpty()) {
                try {
                    if (_timeout == 0) {
                        _backlog.wait();
                    } else {
                        long startTime = System.currentTimeMillis();
                        _backlog.wait(_timeout);
                        if (System.currentTimeMillis() - startTime >= _timeout) {
                            throw new SocketTimeoutException();
                        }
                    }
                } catch (InterruptedException xcp) {
                    throw new InterruptedIOException();
                }

                if (isClosed()) {
                    throw new IOException();
                }
            }

            return _backlog.remove(0);
        }
    }

    @Override
    public synchronized void close() {
        if (isClosed()) {
            return;
        }

        _connectionPool.shutdown();

        _clientSockTable.forEach(new BiConsumer<SocketAddress, ClientHolder>() {
            @Override
            public void accept(SocketAddress address, ClientHolder clientHolder) {
                clientHolder.close();
            }
        });
        _receiverThread.interrupt();
        _closed = true;
        synchronized (_backlog) {
            _backlog.clear();
            _backlog.notify();
        }

        if (_clientSockTable.isEmpty()) {
            _recvChannel.socket().close();
        }

        synchronized (_uuidSockTable) {
            _uuidSockTable.clear();
        }
    }

    /**
     * Registers a new client connection
     *
     * @param endpoint the new client.
     * @return the clientHolder.
     */
    private ClientHolder newConnection(SocketAddress endpoint) {
        ClientHolder holder;
        synchronized (_clientSockTable) {
            holder = _clientSockTable.get(endpoint);
            if (holder == null) {
                holder = new ClientHolder(_recvChannel, endpoint);
                _clientSockTable.put(endpoint, holder);
            } else {
                holder = new ClientHolder(_recvChannel, endpoint);
                _clientSockTable.replace(endpoint, holder);
            }
        }
        return holder;
    }

    /**
     * Registers a new client socket already connected using dtls
     *
     * @param endpoint the new socket.
     * @return the registered socket.
     */
    private SecureReliableClientSocket addClientSocket(SocketAddress endpoint, ClientHolder holder) {
        //Recebe um holder com o necessário para se criar um socket, verifica se já existe este endpoint criado no
        //sistema e retorna seu socket, se não existir, cria o socket, guarda o holder e retorna o socket.
        synchronized (_clientSockTable) {
            ClientHolder h = _clientSockTable.get(endpoint);
            SecureReliableClientSocket sock = h.getSocket();
            if (sock == null) {
                try {
                    sock = new SecureReliableClientSocket(_recvChannel, holder.getSecureTransport(), endpoint, _profile);
                    sock.addStateListener(_stateListener);
                    holder.setSocket(sock);
                    _clientSockTable.replace(endpoint, holder);
                } catch (IOException xcp) {
                    xcp.printStackTrace();
                }
            }
            return sock;
        }
    }

    private boolean hasClientSocket(SocketAddress endpoint) {
        synchronized (_clientSockTable) {
            return _clientSockTable.containsKey(endpoint);
        }
    }

    private ClientHolder removeClientSocket(SocketAddress endpoint) {
        synchronized (_uuidSockTable) {
            _uuidSockTable.values().remove(endpoint);
        }

        synchronized (_clientSockTable) {
            ClientHolder holder = _clientSockTable.remove(endpoint);

            if (_clientSockTable.isEmpty()) {
                if (isClosed()) {
                    _recvChannel.socket().close();
                }
            }

            return holder;
        }
    }

    private class ClientHolder {
        protected Thread processSegment;
        private UUID uuid;
        private SecureReliableClientSocket socket;
        private DTLSTransport secureTransport;
        private ClientTransporter transport;
        private SocketAddress endpoint;
        private BlockingQueue<byte[]> _rcvQueue;

        public ClientHolder(DatagramChannel channel, SocketAddress endpoint) {
            _rcvQueue = new LinkedBlockingQueue<>();
            this.endpoint = endpoint;
            transport = new ClientTransporter(_rcvQueue, channel, endpoint);
        }

        public SecureReliableClientSocket getSocket() {
            return socket;
        }

        public void setSocket(SecureReliableClientSocket socket) {
            this.socket = socket;
        }

        public DTLSTransport getSecureTransport() {
            return secureTransport;
        }

        public ClientTransporter getTransport() {
            return transport;
        }

        public void secureHandshakCompleted(DTLSTransport secureTransport) {
            this.secureTransport = secureTransport;
            this.processSegment = new ProcessSegmentThread(secureTransport, endpoint);
            this.processSegment.start();
        }

        public void receiveRawData(byte[] buffer) {
            try {
                _rcvQueue.put(buffer);
            } catch (InterruptedException e) {
                LOGGER.warning("Client error on receive raw data");
                e.printStackTrace();
            }
        }

        public void close() {
            processSegment.interrupt();
            try {
                secureTransport.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private class ClientTransporter implements DatagramTransport {

        private BlockingQueue<byte[]> _rcvQueue;
        private DatagramChannel _channel;
        private SocketAddress _endpoint;

        public ClientTransporter(BlockingQueue<byte[]> _rcvQueue, DatagramChannel _channel, SocketAddress _endpoint) {
            this._rcvQueue = _rcvQueue;
            this._channel = _channel;
            this._endpoint = _endpoint;
        }

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
            byte[] buff;
            try {
                buff = _rcvQueue.take();
                System.arraycopy(buff, 0, bytes, i, buff.length);
                return buff.length;
            } catch (InterruptedException e) {
                LOGGER.warning("Sync client error on receive raw data");
                e.printStackTrace();
            }
            return -1;
        }

        @Override
        public void send(byte[] bytes, int i, int i1) throws IOException {
            _scheduler.submit(_recvChannel, _endpoint, bytes, i, i1);
        }

        @Override
        public void close() throws IOException {

        }
    }

    private class BufferedPacket {
        private byte[] buf;
        private SocketAddress clientEndpoint;

        public BufferedPacket(byte[] buffer, SocketAddress endpoint) {
            this.buf = buffer;
            this.clientEndpoint = endpoint;
        }

        public byte[] getBuffer() {
            return buf;
        }

        public SocketAddress getClientEndpoint() {
            return clientEndpoint;
        }

    }

    private class ReceiverThread extends Thread {
        public ReceiverThread() {
            super("SecureReliableServerSocket");
            setDaemon(true);
        }

        @Override
        public void run() {
            ByteBuffer buffer = ByteBuffer.allocate(65535);
            Segment segment = null;
            UUID uuid = null;
            byte[] buf = null;
            int tot = -1;

            SocketAddress clientEndpoint = null;
            BufferedPacket bufferedPacket = null;
            ClientHolder holder;

            while (!_closed) {
                try {
                    buffer.clear();
                    clientEndpoint = _recvChannel.receive(buffer);

                    if (clientEndpoint == null) continue;

                    tot = buffer.position();
                    buf = new byte[tot];
                    System.arraycopy(buffer.array(), 0, buf, 0, buf.length);

                    segment = Segment.parse(buf);
                    if (segment instanceof SYNSegment) {
                        _connectionPool.submit(new SecureConnectionTask(clientEndpoint));
                    } else {
                        synchronized (_clientSockTable) {
                            holder = _clientSockTable.get(clientEndpoint);
                        }
                        if (holder != null)
                            holder.receiveRawData(buf);
                        else
                            LOGGER.warning("Unsynchronized client");
                    }
                } catch (Exception ex) {
                    LOGGER.warning("Error on receiving and parsing PKG");
                    ex.printStackTrace();
                } finally {
                    buffer.clear();
                }
            }
        }
    }

    private class SecureConnectionTask implements Runnable {
        private ClientHolder holder;

        public SecureConnectionTask(SocketAddress endpoint) {
            holder = newConnection(endpoint); //TODO verificar reconexão
        }

        @Override
        public void run() {
            try {
                holder.secureHandshakCompleted(_dtlsProtocol.accept(_serverConfig, holder.getTransport()));
            } catch (IOException e) {
                LOGGER.severe("Handshake error");
                e.printStackTrace();
            }
        }
    }

    private class ProcessSegmentThread extends Thread {
        private Segment segment;
        private SocketAddress clientEndpoint;
        private SecureReliableClientSocket sock = null;
        private DTLSTransport secureTransport;
        private byte[] buffer = new byte[65535];

        public ProcessSegmentThread(DTLSTransport secureTransport, SocketAddress endpoint) {
            this.secureTransport = secureTransport;
            this.clientEndpoint = endpoint;
        }

        @Override
        public void run() {
            while (true) {
                try {
                    int len = secureTransport.receive(buffer, 0, buffer.length, 0);
                    this.segment = Segment.parse(buffer, 0, len);
                } catch (IOException e) {
                    LOGGER.warning("Stopping process segment thread.");
                    e.printStackTrace();
                }
                UUID uuid = null;
                SocketAddress oldEndpoint = null;

                // handle UID segment?
                if (segment instanceof UIDSegment) {
                    uuid = ((UIDSegment) segment).getUUID();
                    synchronized (_uuidSockTable) {
                        if (_uuidSockTable.containsKey(uuid)) {
                            oldEndpoint = _uuidSockTable.get(uuid);

                            // Are the Endpoints the same or did the client change IP?
                            if (oldEndpoint.equals(clientEndpoint) == false) {

                                // client changed ip address
                                LOGGER.fine("processing UIDSegment from different endpoint, updating");
                                _uuidSockTable.remove(uuid);
                                _uuidSockTable.put(uuid, clientEndpoint);

                                synchronized (_clientSockTable) {
                                    ClientHolder clientHolder = _clientSockTable.get(oldEndpoint);
                                    SecureReliableClientSocket oldSock = clientHolder.getSocket();
                                    if (oldSock != null) {
                                        _clientSockTable.remove(oldEndpoint);
                                        oldSock.setEndpoint(clientEndpoint);
                                        _clientSockTable.put(clientEndpoint, clientHolder);
                                    }
                                }
                            } else {
                                LOGGER.fine("ignored UIDSegment from same endpoint");
                            }
                        } else {
                            _uuidSockTable.put(uuid, clientEndpoint);
                        }
                    }
                }

                synchronized (_clientSockTable) {
                    if (segment instanceof SYNSegment) {
                        ClientHolder holder = _clientSockTable.get(clientEndpoint);
                        if (holder.getSocket() == null) {
                            sock = addClientSocket(clientEndpoint, holder);
                            holder.setSocket(sock);
                        }
                    }
                    //sock = _clientSockTable.get(clientEndpoint).getSocket();
                }

                if (sock != null) {
                    sock.segmentReceived(segment);
                } else {
                    LOGGER.warning("drop " + segment);
                }
            }
        }
    }


    private class SecureReliableClientSocket extends SecureReliableSocket {
        public SecureReliableClientSocket(DatagramChannel channel, DTLSTransport secureTransport, SocketAddress endpoint, ReliableSocketProfile profile) throws IOException {
            super(channel, secureTransport, endpoint, profile);
        }

        protected void segmentReceived(final Segment segment) {
            scheduleReceive(segment);
        }

        @Override
        protected void log(String msg) {
            LOGGER.fine(getPort() + ": " + msg);
        }

        @Override
        protected void closeSocket() {
        }
    }

    private class StateListener implements ReliableSocketStateListener {
        @Override
        public void connectionOpened(ReliableSocket sock) {
            if (sock instanceof SecureReliableSocket) {
                synchronized (_backlog) {
                    while (_backlog.size() > DEFAULT_BACKLOG_SIZE) {
                        try {
                            _backlog.wait();
                        } catch (InterruptedException xcp) {
                            xcp.printStackTrace();
                        }
                    }

                    _backlog.add(sock);
                    _backlog.notify();
                }
            }
        }

        @Override
        public void connectionRefused(ReliableSocket sock) {
            // do nothing.
        }

        @Override
        public void connectionClosed(ReliableSocket sock) {
            // Remove client socket from the table of active connections.
            if (sock instanceof SecureReliableClientSocket) {
                removeClientSocket(sock.getRemoteSocketAddress());
            }
        }

        @Override
        public void connectionFailure(ReliableSocket sock) {
            // Remove client socket from the table of active connections.
            if (sock instanceof SecureReliableClientSocket) {
                removeClientSocket(sock.getRemoteSocketAddress());
            }
        }

        @Override
        public void connectionReset(ReliableSocket sock) {
            // do nothing.
        }
    }
}
