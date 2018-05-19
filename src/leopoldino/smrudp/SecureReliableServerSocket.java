package leopoldino.smrudp;

import net.rudp.*;
import net.rudp.impl.SYNSegment;
import net.rudp.impl.Segment;
import net.rudp.impl.UIDSegment;


import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
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

public class SecureReliableServerSocket extends ReliableServerSocket {
    /**
     * LOGGER
     */
    public static final Logger LOGGER = Logger.getLogger(SecureReliableServerSocket.class.getCanonicalName());
    static private ExecutorService _recvTaskPool;
    static private ExecutorService _connectionPool;
    /* A table of active opened client sockets. */
    private final HashMap<SocketAddress, ReliableClientSocket> _clientSockTable;
    private ReceiverThread _receiverThread;
    private int _sendBufferSize;
    private int _recvBufferSize;
    private SecureReliableSocketStateListener _secureStateListener;

    private SecurityProfile securityProfile;


    public SecureReliableServerSocket(int port, SecurityProfile securityProfile) throws IOException {
        this(port, 0, null, new ReliableSocketProfile(), securityProfile);
    }

    public SecureReliableServerSocket(int port, ReliableSocketProfile profile, SecurityProfile securityProfile) throws IOException {
        this(port, 0, null, profile, securityProfile);
    }

    public SecureReliableServerSocket(int port, int backlog, SecurityProfile securityProfile) throws IOException {
        this(port, backlog, null, new ReliableSocketProfile(), securityProfile);
    }

    public SecureReliableServerSocket(int port, int backlog, InetAddress bindAddr, ReliableSocketProfile profile, SecurityProfile securityProfile) throws IOException {
        super(new InetSocketAddress(bindAddr, port), backlog, profile, null, new TreeMap<UUID, SocketAddress>());

        _stateListener = new StateListener();
        _secureStateListener = new SecureStateListener();
        _clientSockTable = new HashMap<SocketAddress, ReliableClientSocket>();

        _timeout = 0;
        _closed = false;

        _sendBufferSize = (_profile.maxSegmentSize() - Segment.RUDP_HEADER_LEN) * _profile.maxRecvQueueSize();
        _recvBufferSize = (_profile.maxSegmentSize() - Segment.RUDP_HEADER_LEN) * _profile.maxSendQueueSize();

        if (_recvTaskPool == null) {
            _recvTaskPool = Executors.newFixedThreadPool(32, new AsyncScheduler.ScheduleFactory("Receive Data"));
        }

        if (_connectionPool == null) {
            _connectionPool = Executors.newFixedThreadPool(32, new AsyncScheduler.ScheduleFactory("In Connection"));
        }

        this.securityProfile = securityProfile;

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

        _clientSockTable.forEach(new BiConsumer<SocketAddress, ReliableClientSocket>() {
            @Override
            public void accept(SocketAddress address, ReliableClientSocket client) {
                try {
                    client.close();
                } catch (IOException e) {
                    LOGGER.warning("Cannot close the socket");
                    e.printStackTrace();
                }
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
    private ReliableClientSocket addClientSocket(SocketAddress endpoint) {
        synchronized (_clientSockTable) {
            ReliableClientSocket sock = _clientSockTable.get(endpoint);
            if (sock == null) {
                try {
                    sock = new ReliableClientSocket(_recvChannel, endpoint, _profile);
                    sock.addStateListener(_stateListener);
                    sock.addSecureStateListener(_secureStateListener);
                    //sock.connect(endpoint);
                    _clientSockTable.put(endpoint, sock);
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
    private ReliableClientSocket removeClientSocket(SocketAddress endpoint) {
        synchronized (_uuidSockTable) {
            _uuidSockTable.values().remove(endpoint);
        }

        synchronized (_clientSockTable) {
            ReliableClientSocket client = _clientSockTable.remove(endpoint);

            if (_clientSockTable.isEmpty()) {
                if (isClosed()) {
                    _recvChannel.socket().close();
                }
            }

            return client;
        }
    }

    /**
     * Aqui o servidor recebe todos os pacotes
     */

    private class ReceiverThread extends Thread {

        public ReceiverThread() {
            super("Receiver Thread");
            super.setDaemon(true);
        }

        @Override
        public void run()
        {
            while (!SecureReliableServerSocket.super._closed)
            {
                try
                {
                    ByteBuffer data = ByteBuffer.allocate(65535); //TODO Da pra ganhar memória otimizando esse tamanho
                    SocketAddress address = _recvChannel.receive(data);
                    if (address == null)
                        continue;
                    //data.flip();
                    _recvTaskPool.submit(new ReceiveTask(data, address));
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * Já aqui ele processa estes pacotes
     */

    private class ReceiveTask implements Runnable
    {
        private ByteBuffer data;
        private SocketAddress clientEndpoint;

        public ReceiveTask(ByteBuffer data, SocketAddress clientAddress) {
            this.data = data;
            this.clientEndpoint = clientAddress;
        }


        //Aqui se concentra
        @Override
        public void run() {
            Segment segment = Segment.tryParse(this.data.array(), 0, this.data.position());
            ReliableClientSocket holder = null;

            if (segment != null) {

                //Se for um segment plano sobre UUID, então realiza um handover no servidor
                if (segment instanceof UIDSegment) {
                    UUID uuid = ((UIDSegment) segment).getUUID();

                    synchronized (SecureReliableServerSocket.super._uuidSockTable) {
                        if (SecureReliableServerSocket.super._uuidSockTable.containsKey(uuid)) {
                            SocketAddress oldEndpoint = SecureReliableServerSocket.super._uuidSockTable.get(uuid);
                            if (oldEndpoint != clientEndpoint) {
                                LOGGER.fine("processing UIDSegment from different endpoint, updating");
                                _uuidSockTable.remove(uuid);
                                _uuidSockTable.put(uuid, clientEndpoint);


                                synchronized (SecureReliableServerSocket.this._clientSockTable) {
                                    ReliableClientSocket client = SecureReliableServerSocket.this._clientSockTable.get(oldEndpoint);
                                    if (client != null) {
                                        SecureReliableServerSocket.this._clientSockTable.remove(oldEndpoint);
                                        client.setEndpoint(clientEndpoint);
                                        SecureReliableServerSocket.this._clientSockTable.put(clientEndpoint, client);
                                    }
                                }
                            } else {
                                LOGGER.fine("ignored UIDSegment from same endpoint");
                            }
                        } else {
                            SecureReliableServerSocket.super._uuidSockTable.put(uuid, clientEndpoint);
                        }
                    }
                } else {
                    synchronized (SecureReliableServerSocket.this._clientSockTable) {
                        if (segment instanceof SYNSegment) {
                            if (!SecureReliableServerSocket.this._clientSockTable.containsKey(clientEndpoint)) {
                                holder = addClientSocket(clientEndpoint);
                            }
                        }
                        holder = SecureReliableServerSocket.this._clientSockTable.get(clientEndpoint);
                    }

                    if (holder != null)
                    {
                        /**
                         * TODO Preparar este caso pra os segmentos SYN e UID sem entrar na classe socket
                         *
                         * Se o socket estiver em modo protegido e ocorrer um handover, a classe tentará enviar o ACK
                         * através do canal seguro, que pode não estar funcionando.
                         *
                         * As vezes tem como fazer um switch disso
                         *
                         *
                         * Hipotese 1
                         * Qualquer pacote SYN e UID ser tratado por fora do DTLS, às vezes até o ACK.
                         * Simplesmente enviando estes pacotes por fora do DTLS.
                         *
                         *
                         */
                        holder.segmentReceived(segment);
                    }
                    else {
                        LOGGER.warning("drop " + segment);
                    }
                }
            }
            //Se for um conteudo protegido
            else
            {
                synchronized (SecureReliableServerSocket.this._clientSockTable)
                {
                    if (SecureReliableServerSocket.this._clientSockTable.containsKey(clientEndpoint)) {
                        holder = SecureReliableServerSocket.this._clientSockTable.get(clientEndpoint);

                        if (holder != null)
                        {
                            holder.receiveRawData(data);
                        }
                        else {
                            LOGGER.warning("Secure data drop ");
                        }
                    }
                    else
                        LOGGER.warning("Drop data by not find the endpoint");
                }
            }
        }

    }

    private class ReliableClientSocket extends SecureReliableSocket {
        public ReliableClientSocket(DatagramChannel channel, SocketAddress endpoint, ReliableSocketProfile profile) throws IOException {
            super(channel, profile, SecureReliableServerSocket.this.securityProfile);
            super.turnAServer();
            this.setEndpoint(endpoint);
        }

        protected void segmentReceived(final Segment segment) {
            this.scheduleReceive(segment);
        }

        @Override
        protected void log(String msg) {
            LOGGER.fine(getPort() + ": " + msg);
        }

        @Override
        protected void closeSocket() {
        }

        @Override
        protected SelectionKey register() {
            return null;
        }
    }

    private class StateListener implements ReliableSocketStateListener {
        @Override
        public void connectionOpened(ReliableSocket sock) {
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

    private class SecureStateListener implements SecureReliableSocketStateListener
    {

        @Override
        public void firstHandshakeConcluded(SecureReliableSocket sock) {
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
}
