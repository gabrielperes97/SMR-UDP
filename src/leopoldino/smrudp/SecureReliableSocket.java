package leopoldino.smrudp;

import net.rudp.ReliableSocket;
import net.rudp.ReliableSocketListener;
import net.rudp.ReliableSocketProfile;
import net.rudp.ReliableSocketStateListener;
import net.rudp.impl.*;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN;

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
    protected Lock handshakeLock;
    protected Thread handshakeThread;

    protected SSLEngine sslEngine;
    protected SecurityProfile securityProfile;
    protected List<SecureReliableSocketStateListener> secureStateListeners;
    private boolean serverMode = false;
    private boolean serverConnected = false;
    protected Object serverLock = new Object();

    //Raw data received from UDP
    protected LinkedBlockingQueue<ByteBuffer> receivedQueue;

    public SecureReliableSocket(SecurityProfile securityProfile) throws IOException {
        this(new ReliableSocketProfile(), securityProfile);
    }

    public SecureReliableSocket(int bindPort, SecurityProfile securityProfile) throws IOException {
        super(DatagramChannel.open().bind(new InetSocketAddress(bindPort)), new ReliableSocketProfile(), SecureScheduler.getSecureScheduler());
        init(securityProfile);
        turnAServer();
    }

    public SecureReliableSocket(ReliableSocketProfile profile, SecurityProfile securityProfile) throws IOException {
        this(DatagramChannel.open(), profile, securityProfile);
    }

    public SecureReliableSocket(String host, int port, SecurityProfile securityProfile) throws IOException {
        this(DatagramChannel.open(), new InetSocketAddress(host, port), new ReliableSocketProfile(), securityProfile);
    }

    protected SecureReliableSocket(DatagramChannel channel, SecurityProfile securityProfile) {
        this(channel, new ReliableSocketProfile(), securityProfile);
    }

    protected SecureReliableSocket(DatagramChannel channel, ReliableSocketProfile profile, SecurityProfile securityProfile) {
        super(channel, profile, SecureScheduler.getSecureScheduler());
        //Scheduler null
        init(securityProfile);
    }

    public SecureReliableSocket(DatagramChannel channel, SocketAddress endpoint, ReliableSocketProfile profile, SecurityProfile securityProfile) throws IOException {
        super(channel, profile, SecureScheduler.getSecureScheduler());
        init(securityProfile);
        connect(endpoint);
    }

    private void init(SecurityProfile securityProfile) {
        secureScheduler = (SecureScheduler) _scheduler;
        this.receiveThread = new ReceiveThread();
        this.receivedQueue = new LinkedBlockingQueue<>();
        this.secureStateListeners = new LinkedList<>();
        super.addStateListener(new MrudpStateListener());
        this.securityProfile = securityProfile;
        this.sslEngine = this.securityProfile.getContext().createSSLEngine();
        this.sslEngine.setUseClientMode(false);
        this.handshakeLock = new ReentrantLock();
        this.handshakeThread = new HandshakeHandler();

        SSLSession sslSession = this.sslEngine.getSession();
        inAppData = ByteBuffer.allocate(sslSession.getApplicationBufferSize());
        outAppData = ByteBuffer.allocate(sslSession.getApplicationBufferSize());
        inNetData = ByteBuffer.allocate(sslSession.getPacketBufferSize());
        outNetData = ByteBuffer.allocate(sslSession.getPacketBufferSize());
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
        //TODO botar pra esperar o handshake aqui
    }

    public void turnAServer()
    {
        this.sslEngine.setUseClientMode(true);
        _key = register();
    }


    @Override
    protected void closeSocket() {
        super.closeSocket();
    }

    @Override
    protected SelectionKey register() {
        return this.secureScheduler.register(this._channel, this);
    }

    public void addSecureStateListener(SecureReliableSocketStateListener stateListener) {
        if (stateListener == null) { throw new NullPointerException("secureStateListener"); }

        synchronized (this.secureStateListeners) {
            if (!this.secureStateListeners.contains(stateListener)) {
                this.secureStateListeners.add(stateListener);
            }
        }
    }


    public void removeSecureStateListener(SecureReliableSocketStateListener stateListener) {
        if (stateListener == null) { throw new NullPointerException("secureStateListener"); }

        synchronized (this.secureStateListeners) {
            this.secureStateListeners.remove(stateListener);
        }
    }

    @Override
    protected void submitSegment(Segment segment) {
        /**
         * TODO Durante a fase inicial de conexão e durante handovers, o protocolo necessita enviar pacotes por fora do DTLS
         * Para isso é necessário que se tenha uma função para eles
         */
        if (segment instanceof SYNSegment || segment instanceof ACKSegment || segment instanceof UIDSegment || segment instanceof NULSegment || segment instanceof FINSegment)
        {
            this.secureScheduler.submit(this._channel, this._endpoint, ByteBuffer.wrap(segment.getBytes()));
            //System.out.println("Sending segment: "+segment.toString());
            return;
        }

        //Ve se tem handshake, se tiver, acorda a trhead que cuida disso,
        //senão envia logo
        System.out.println("Sending secure segment: "+segment.toString());
        SSLEngineResult.HandshakeStatus hs = sslEngine.getHandshakeStatus();
        if (hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING && hs != SSLEngineResult.HandshakeStatus.FINISHED)
        {
            if (!handshakeThread.isAlive())
                handshakeThread.start();
            try {
                synchronized (handshakeLock) {
                    handshakeLock.wait();
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

        }
        //handshakeLock.lock();
        outAppData.clear();
        outAppData.put(segment.getBytes());
        try {
            while (outAppData.hasRemaining()) {
                SSLEngineResult res = sslEngine.wrap(outAppData, outNetData);
                {
                    switch (res.getStatus()) {
                        case OK:
                            this.secureScheduler.submit(this._channel, this._endpoint, outAppData);
                            break;
                        case BUFFER_OVERFLOW:
                            int appSize = sslEngine.getSession().getApplicationBufferSize();
                            if (appSize > outAppData.capacity()) {
                                ByteBuffer b = ByteBuffer.allocate(appSize);
                                outAppData.flip();
                                b.put(outAppData);
                                outAppData = b;
                            }


                            int netSize = sslEngine.getSession().getPacketBufferSize();
                            if (netSize > outNetData.capacity()) {
                                //enlarge the peer network packet buffer
                                ByteBuffer b = ByteBuffer.allocate(netSize);
                                outNetData.flip();
                                b.put(outNetData);
                                outNetData = b;
                                //System.out.println("When Buffer Underflow");
                            }
                            break;
                    }
                }
            }
            //this.secureScheduler.submit(this._channel, this._endpoint, ByteBuffer.wrap(segment.getBytes()));
        } catch (SSLException e) {
            e.printStackTrace();
        }
        //handshakeLock.unlock();
    }

    @Override
    protected void scheduleReceive(Segment segment)
    {
        //System.out.println("Receiving segment: "+segment.toString());
        super.scheduleReceive(segment);
    }


    protected void setEndpoint(SocketAddress endpoint) {
        _endpoint = endpoint;
    }

    public SSLEngine getSslEngine() {
        return sslEngine;
    }

    public int getNetBufferSize()
    {
        return this.sslEngine.getSession().getPacketBufferSize();
    }

    protected void receiveRawData(ByteBuffer data)
    {
        System.out.println("Secure data received");
        receivedQueue.offer(data);
    }

    //Verifica constantemente o status do handshake para algum tratamento
    private class HandshakeHandler extends Thread {

        private boolean firstHandshake = true;

        @Override
        public void start()
        {
            //handshakeLock.lock();
            super.start();
        }

        @Override
        public void run() {
            SSLEngineResult.HandshakeStatus hs = sslEngine.getHandshakeStatus();

            ByteBuffer data = null;
            try {
                while (hs != SSLEngineResult.HandshakeStatus.FINISHED && hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                    switch (hs) {
                        case NEED_UNWRAP:
                            data = receivedQueue.poll();
                            if (data == null)
                                break;
                            //data.flip();
                            System.out.println("Receveu");
                        case NEED_UNWRAP_AGAIN:
                            inAppData.clear();
                            SSLEngineResult res = sslEngine.unwrap(data, inAppData);
                            data.compact();
                            System.out.println("Fez o unwrap: "+res.getStatus());

                            switch (res.getStatus()) {
                                case CLOSED:
                                    //UdpCommon.whenSSLClosed();
                                    break;
                                case BUFFER_OVERFLOW:
                                    //UdpCommon.whenBufferOverflow(sslEngine, inAppData);
                                    break;
                                case BUFFER_UNDERFLOW:
                                    //UdpCommon.whenBufferUnderflow(sslEngine, inNetData);
                                    break;
                            }
                            break;
                        case NEED_WRAP:
                            outNetData.clear();
                            res = sslEngine.wrap(outAppData, outNetData);
                            outNetData.flip();
                            System.out.println("Fez o wrap");
                            switch (res.getStatus()) {
                                case OK:
                                    SecureReliableSocket.this.secureScheduler.submit(SecureReliableSocket.this._channel, SecureReliableSocket.this._endpoint, outNetData);
                                    System.out.println("Enviou");
                                    break;
                                case CLOSED:
                                    //UdpCommon.whenSSLClosed();
                                    break;
                                case BUFFER_OVERFLOW:
                                    //UdpCommon.whenBufferOverflow(sslEngine, buffers.outAppData);

                                    int appSize = sslEngine.getSession().getApplicationBufferSize();
                                    if (appSize > outAppData.capacity()) {
                                        ByteBuffer b = ByteBuffer.allocate(appSize);
                                        //outAppData.flip();
                                        b.put(outAppData);
                                        outAppData = b;
                                    }


                                    int netSize = sslEngine.getSession().getPacketBufferSize();
                                    if (netSize > outNetData.capacity()) {
                                        //enlarge the peer network packet buffer
                                        ByteBuffer b = ByteBuffer.allocate(netSize);
                                        //outNetData.flip();
                                        b.put(outNetData);
                                        outNetData = b;
                                        //System.out.println("When Buffer Underflow");
                                    }
                                    break;
                                case BUFFER_UNDERFLOW:
                                    //UdpCommon.whenBufferUnderflow(sslEngine, outNetData);
                                    break;
                            }
                            break;
                        case NEED_TASK:
                            Runnable task;
                            while ((task = sslEngine.getDelegatedTask()) != null) {
                                //new Thread(task).start();
                                task.run();
                            }
                            break;
                        default:
                            break;
                    }
                    hs = sslEngine.getHandshakeStatus();
                }
                if (firstHandshake)
                {
                    firstHandshake = false;
                    Iterator it = SecureReliableSocket.this.secureStateListeners.iterator();
                    while (it.hasNext()) {
                        SecureReliableSocketStateListener l = (SecureReliableSocketStateListener) it.next();
                        l.firstHandshakeConcluded(SecureReliableSocket.this);
                    }
                }
                System.out.println("Handshake suceffully");
            } catch (SSLException e) {
                e.printStackTrace();
            } finally {
                handshakeLock.notifyAll();
                //handshakeLock.unlock();
            }
        }
    }

    private class ReceiveThread extends Thread
    {
        @Override
        public void run() {
            while (true) {
                SSLEngineResult.HandshakeStatus hs = sslEngine.getHandshakeStatus();
                //Se não está ocorrendo nenhum handshake, nem está em modo seguro ainda.
                ByteBuffer data = receivedQueue.peek();
                if (data != null) {
                    Segment segment = Segment.tryParse(data.array(), 0, data.position());
                    if (segment != null) {
                        SecureReliableSocket.this.scheduleReceive(segment);
                        receivedQueue.poll();
                        continue;
                    } else if (hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING || hs == SSLEngineResult.HandshakeStatus.FINISHED) {
                        try {
                            SSLEngineResult res = sslEngine.unwrap(data, inAppData);
                            switch (res.getStatus()) {
                                case OK:
                                    segment = Segment.parse(data.array(), 0, data.position());
                                    SecureReliableSocket.this.scheduleReceive(segment);
                                    break;
                                case BUFFER_OVERFLOW:
                                    int appSize = sslEngine.getSession().getApplicationBufferSize();
                                    if (appSize > inAppData.capacity()) {
                                        ByteBuffer b = ByteBuffer.allocate(appSize);
                                        //inAppData.flip();
                                        b.put(outAppData);
                                        inAppData = b;
                                    }
                                    break;
                            }
                        } catch (SSLException e) {
                            e.printStackTrace();
                        } finally {
                            receivedQueue.poll();
                        }
                    } else {
                        if (!handshakeThread.isAlive())
                            handshakeThread.start();
                    }
                }

            }
        }
    }

    private class MrudpStateListener implements ReliableSocketStateListener
    {

        @Override
        public void connectionOpened(ReliableSocket sock) {
            try {
                SecureReliableSocket.this.sslEngine.beginHandshake();
                if (!handshakeThread.isAlive())
                    handshakeThread.start();
            } catch (SSLException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void connectionRefused(ReliableSocket sock) {

        }

        @Override
        public void connectionClosed(ReliableSocket sock) {

        }

        @Override
        public void connectionFailure(ReliableSocket sock) {

        }

        @Override
        public void connectionReset(ReliableSocket sock) {

        }
    }
}
