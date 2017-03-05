package leopoldino.smrudp;

import leopoldino.smrudp.impl.NioUdpTransport;
import net.rudp.*;
import net.rudp.impl.SYNSegment;
import net.rudp.impl.Segment;
import net.rudp.impl.UIDSegment;
import org.bouncycastle.crypto.tls.DTLSServerProtocol;
import org.bouncycastle.crypto.tls.DTLSTransport;
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.function.BiConsumer;
import java.util.logging.Logger;

/**
 * This class implements a Secure Server Socket for a ReliableSocket. It is implemented using
 * Bouncy Castle DTLS implementation. To use, implement a TlsServer object, in the
 * tests we have an example about how to implement this.
 *
 * @author Gabriel Leopoldino
 */

//TODO This class works, but need be revised
//TODO Test change of endpoint of a client
public class SecureReliableServerSocket extends ReliableServerSocket {
    /**
     * LOGGER
     */
    public static final Logger LOGGER = Logger.getLogger(SecureReliableServerSocket.class.getCanonicalName());
    static private ExecutorService _connectionPool;
    static private ExecutorService _recvSegmentPool;
    /* A table of active opened client sockets. */
    private final HashMap<SocketAddress, ClientHolder> _clientSockTable;
    private NioUdpTransport _transport;
    private DTLSServerProtocol _dtlsProtocol;
    private TlsServer _serverConfig;
    private ReceiverThread _receiverThread;
    private int _sendBufferSize;
    private int _recvBufferSize;
    private byte[] _recvBuffer;

    /**
     * Specific Functions
     */
    private int _recvBufferOffset;
    private int _recvBufferLen;
    private Semaphore _bufferLocker = new Semaphore(1);

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

        _sendBufferSize = (_profile.maxSegmentSize() - Segment.RUDP_HEADER_LEN) * _profile.maxRecvQueueSize();
        _recvBufferSize = (_profile.maxSegmentSize() - Segment.RUDP_HEADER_LEN) * _profile.maxSendQueueSize();
        _serverConfig = server;
        _transport = new NioUdpTransport(_recvChannel, _sendBufferSize, _recvBufferSize);
        _dtlsProtocol = new DTLSServerProtocol(secureRandom);

        if (_connectionPool == null) {
            _connectionPool = Executors.newFixedThreadPool(32, new AsyncScheduler.ScheduleFactory("In Connection"));
        }

        if (_recvSegmentPool == null) {
            _recvSegmentPool = Executors.newFixedThreadPool(32, new AsyncScheduler.ScheduleFactory("Receive-Segment"));
        }

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

    private ClientHolder newConnection(SocketAddress endpoint) {
        ClientHolder holder;
        synchronized (_clientSockTable) {
            holder = _clientSockTable.get(endpoint);
            if (holder == null) {
                holder = new ClientHolder(_recvChannel, _recvBufferSize, _sendBufferSize, endpoint);
                _clientSockTable.put(endpoint, holder);
            } else {
                holder = new ClientHolder(_recvChannel, _recvBufferSize, _sendBufferSize, endpoint);
                _clientSockTable.replace(endpoint, holder);
            }
        }
        return holder;
    }

    private boolean hasClientSocket(SocketAddress endpoint) {
        synchronized (_clientSockTable) {
            return _clientSockTable.containsKey(endpoint);
        }
    }

    private void processReceiver(byte[] buffer, int off, int len, SocketAddress endpoint) {
        ClientHolder holder;
        synchronized (_clientSockTable) {
            holder = _clientSockTable.get(endpoint);
        }

        if (holder == null)
            newConnection(endpoint);
        try {
            _bufferLocker.acquire();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        _recvBuffer = buffer.clone();
        _recvBufferOffset = off;
        _recvBufferLen = len;
        holder.sendReceiveSignal();

    }

    @Override
    public synchronized void close() {
        if (isClosed()) {
            return;
        }

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
     * Registers a new client socket with the specified endpoint address.
     *
     * @param endpoint the new socket.
     * @return the registered socket.
     */
    private ReliableClientSocket addClientSocket(SocketAddress endpoint, ClientHolder holder) {
        //Recebe um holder com o necessário para se criar um socket, verifica se já existe este endpoint criado no
        //sistema e retorna seu socket, se não existir, cria o socket, guarda o holder e retorna o socket.
        synchronized (_clientSockTable) {
            ClientHolder h = _clientSockTable.get(endpoint);
            ReliableClientSocket sock = holder.getSocket();
            if (sock == null) {
                try {
                    sock = new ReliableClientSocket(_recvChannel, holder.getTransport(), holder.getSecureTransport(), endpoint, _profile);
                    sock.addStateListener(_stateListener);
                    //sock.connect(endpoint);
                    holder.setSocket(sock);
                    _clientSockTable.replace(endpoint, holder);
                } catch (IOException xcp) {
                    xcp.printStackTrace();
                }
            }

            return sock;
        }
    }

    /**
     * Deregisters a client socket with the specified endpoint address.
     *
     * @param endpoint the socket.
     * @return the deregistered socket.
     */
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

    private class ReceiverThread extends Thread {

        public ReceiverThread() {
            super("Receiver Thread");
        }

        @Override
        public void run() {
            ByteBuffer buffer = ByteBuffer.allocate(65535);
            SocketAddress clientEndpoint = null;
            Segment segment = null;
            while (!_closed) {
                try {
                    buffer.clear();
                    clientEndpoint = _recvChannel.receive(buffer);
                    if (clientEndpoint == null)
                        continue;
                    buffer.flip();
                    segment = Segment.parse(buffer.array(), buffer.arrayOffset(), buffer.limit());
                    if (segment instanceof SYNSegment) {
                        _connectionPool.submit(new ConnectionTask(clientEndpoint));
                    } else {
                        processReceiver(buffer.array(), buffer.arrayOffset(), buffer.limit(), clientEndpoint);
                    }

                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private class ConnectionTask implements Runnable {
        private SocketAddress endpoint;
        private ClientHolder holder;

        public ConnectionTask(SocketAddress endpoint) {
            this.endpoint = endpoint;
            holder = newConnection(endpoint);
        }

        public void run() {
            try {
                holder.setSecureTransport(_dtlsProtocol.accept(_serverConfig, holder.transport));
                holder.secureReceiverThread = new SecureReceiverThread(holder.getSecureTransport(), endpoint);
                holder.secureReceiverThread.start();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private class ReceiveTransport extends NioUdpTransport {
        protected Semaphore lock;

        public ReceiveTransport(DatagramChannel channel, int receiveLimit, int sendLimit, SocketAddress endpoint) throws InterruptedException {
            super(channel, receiveLimit, sendLimit, endpoint);
            lock = new Semaphore(1);
            lock.acquire();
        }

        @Override
        public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException {
            try {
                lock.acquire();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            synchronized (_recvBuffer) {
                int j = off;
                for (int i = _recvBufferOffset; i < _recvBufferLen; i++) {
                    buf[j] = _recvBuffer[i];
                    j++;
                }
            }
            _bufferLocker.release();
            return len;
        }

        public void signal() {
            lock.release();
        }
    }

    private class ClientHolder {
        protected Thread secureReceiverThread;
        private UUID uuid;
        private ReceiveTransport transport;
        private ReliableClientSocket socket;
        private DTLSTransport secureTransport;

        public ClientHolder(DatagramChannel channel, int receiveLimit, int sendLimit, SocketAddress endpoint) {
            try {
                transport = new ReceiveTransport(channel, receiveLimit, sendLimit, endpoint);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        public void sendReceiveSignal() {
            transport.signal();
        }

        public UUID getUuid() {
            return uuid;
        }

        public void setUuid(UUID uuid) {
            this.uuid = uuid;
        }

        public ReliableClientSocket getSocket() {
            return socket;
        }

        public void setSocket(ReliableClientSocket socket) {
            this.socket = socket;
        }

        public ReceiveTransport getTransport() {
            return transport;
        }

        public void setTransport(ReceiveTransport transport) {
            this.transport = transport;
        }

        public DTLSTransport getSecureTransport() {
            return secureTransport;
        }

        public void setSecureTransport(DTLSTransport secureTransport) {
            this.secureTransport = secureTransport;
        }

        public void close() {
            secureReceiverThread.interrupt();
            try {
                secureTransport.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private class SecureReceiverThread extends Thread {
        private DTLSTransport transport;
        private byte[] buffer;
        private SocketAddress endpoint;

        public SecureReceiverThread(DTLSTransport transport, SocketAddress endpoint) {
            super("Secure receiver thread " + endpoint);
            this.transport = transport;
            this.endpoint = endpoint;
            buffer = new byte[_recvBufferSize];
        }

        @Override
        public void run() {
            Segment segment;
            int len;
            while (!_closed) {
                try {
                    len = transport.receive(buffer, 0, _recvBufferSize, 0);
                    segment = Segment.parse(buffer, 0, len);
                    _recvSegmentPool.submit(new ProcessSegmentTask(segment, endpoint, transport));
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private class ProcessSegmentTask implements Runnable {
        private Segment segment;
        private SocketAddress clientEndpoint;
        private DTLSTransport secureTransport;

        public ProcessSegmentTask(Segment segment, SocketAddress clientEndpoint, DTLSTransport secureTransport) {
            this.segment = segment;
            this.clientEndpoint = clientEndpoint;
            this.secureTransport = secureTransport;
        }

        @Override
        public void run() {
            UUID uuid = null;
            ReliableClientSocket sock = null;
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
                                ReliableClientSocket oldSock = clientHolder.getSocket();
                                if (oldSock != null) { //TODO Test this
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
                sock = _clientSockTable.get(clientEndpoint).getSocket();
            }

            if (sock != null) {
                sock.segmentReceived(segment);
            } else {
                LOGGER.warning("drop " + segment);
            }
        }
    }

    private class ReliableClientSocket extends SecureReliableSocket {
        public ReliableClientSocket(DatagramChannel channel, NioUdpTransport transport, DTLSTransport secureTransport, SocketAddress endpoint, ReliableSocketProfile profile) throws IOException {
            super(channel, transport, secureTransport, endpoint, profile);
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
            if (sock instanceof ReliableClientSocket) {
                removeClientSocket(sock.getRemoteSocketAddress());
            }
        }

        @Override
        public void connectionFailure(ReliableSocket sock) {
            // Remove client socket from the table of active connections.
            if (sock instanceof ReliableClientSocket) {
                removeClientSocket(sock.getRemoteSocketAddress());
            }
        }

        @Override
        public void connectionReset(ReliableSocket sock) {
            // do nothing.
        }
    }
}
