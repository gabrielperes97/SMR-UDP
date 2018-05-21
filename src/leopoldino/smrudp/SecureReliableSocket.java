package leopoldino.smrudp;

import net.rudp.*;
import net.rudp.impl.*;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus.FINISHED;
import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN;
import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;

/**
 * This class implements a Secure Socket using a Reliable Socket. It's use the
 * Java Secure Socket Extension (JSSE). Working fine in non-blocking mode.
 * @author Gabriel Leopoldino
 */
public class SecureReliableSocket extends ReliableSocket {

    protected ByteBuffer outAppData;
    protected ByteBuffer outNetData;
    protected ByteBuffer inAppData;
    protected ByteBuffer inNetData;
    protected Lock handshakeLock;
    protected Condition hasHandshake;
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
        super(DatagramChannel.open().bind(new InetSocketAddress(bindPort)), new ReliableSocketProfile());
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
        super(channel, profile);
        //Scheduler null
        init(securityProfile);
    }

    public SecureReliableSocket(DatagramChannel channel, SocketAddress endpoint, ReliableSocketProfile profile, SecurityProfile securityProfile) throws IOException {
        super(channel, profile);
        init(securityProfile);
        connect(endpoint);
    }

    private void init(SecurityProfile securityProfile) {
        this.receivedQueue = new LinkedBlockingQueue<>();
        this.secureStateListeners = new LinkedList<>();
        this.securityProfile = securityProfile;
        this.sslEngine = this.securityProfile.getContext().createSSLEngine();
        this.sslEngine.setUseClientMode(true);
        this.handshakeLock = new ReentrantLock();
        this.hasHandshake = this.handshakeLock.newCondition();
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

        super.connect(endpoint, timeout);
        super._out = new ReliableSocketOutputStream(this);
        super._in = new ReliableSocketInputStream(this);
        try {
            SecureReliableSocket.this.sslEngine.beginHandshake();
            if (!handshakeThread.isAlive())
                handshakeThread.start();
            handshakeLock.lock();
            hasHandshake.await();
            handshakeLock.unlock();
        } catch (SSLException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        /*synchronized (handshakeLock) {
            try {
                handshakeLock.wait();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }*/
        //TODO botar pra esperar o handshake aqui
    }

    public void turnAServer()
    {
        this.sslEngine.setUseClientMode(false);
        _key = register();
    }

    protected SSLEngine getSslEngine() {
        return sslEngine;
    }

    @Override
    protected void closeSocket() {
        super.closeSocket();
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
    protected int read(byte[] b, int off, int len) throws IOException {

        SSLEngineResult.HandshakeStatus hs = sslEngine.getHandshakeStatus();
        if (hs != FINISHED && hs != NOT_HANDSHAKING)
        {
            if (!handshakeThread.isAlive())
                handshakeThread.start();
            try {
                handshakeLock.lock();
                hasHandshake.await();
                handshakeLock.unlock();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            //TODO Trava até terminar o handshake
        }

        //TODO transformar isso em locks de out
        synchronized (inNetData)
        {
            inNetData.clear();
            int i = super.read(inNetData.array(), inNetData.arrayOffset(), inNetData.limit());
            if (i > 0) {
                inNetData.position(inNetData.arrayOffset() + i);

                synchronized (inAppData) {
                    SSLEngineResult res = null;
                    while (res == null || res.getStatus() != SSLEngineResult.Status.OK) {
                        res = sslEngine.unwrap(inNetData, inAppData);
                        switch (res.getStatus()) {
                            case BUFFER_OVERFLOW:
                                int appSize = sslEngine.getSession().getApplicationBufferSize();
                                if (appSize > inAppData.capacity()) {
                                    ByteBuffer buffer = ByteBuffer.allocate(appSize);
                                    //inAppData.flip();
                                    buffer.put(inAppData);
                                    inAppData = buffer;
                                }
                                break;
                            case BUFFER_UNDERFLOW:
                                i = super.read(inNetData.array(), inNetData.arrayOffset() + i, inNetData.limit());
                                inNetData.position(inNetData.arrayOffset() + i);
                                break;
                            case CLOSED:
                                LOGGER.severe("Aí fudeu");
                        }
                    }
                    System.arraycopy(inAppData.array(), inAppData.arrayOffset(), b, off, inAppData.position());
                    return inAppData.position() - inAppData.arrayOffset();
                }
            }
            else
                return -1;
        }
    }

    @Override
    protected int write(byte[] b, int off, int len) throws IOException {
        SSLEngineResult.HandshakeStatus hs = sslEngine.getHandshakeStatus();
        if (hs != FINISHED && hs != NOT_HANDSHAKING)
        {
            if (!handshakeThread.isAlive())
                handshakeThread.start();
            try {
                handshakeLock.lock();
                hasHandshake.await();
                handshakeLock.unlock();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            //TODO Trava até terminar o handshake
        }

        synchronized (outAppData)
        {
            synchronized (outNetData) {
                outNetData.clear();
                outAppData.clear();
                outAppData.put(b, off, len);
                outAppData.flip();


                while (outAppData.hasRemaining()) {
                    SSLEngineResult res = null;
                    while (res == null || res.getStatus() != SSLEngineResult.Status.OK) {
                        res = sslEngine.wrap(outAppData, outNetData);
                        switch (res.getStatus()) {
                            case OK:
                                System.out.println("Enviando dados");
                                return super.write(outNetData.array(), outNetData.arrayOffset(), res.bytesProduced());
                            case BUFFER_OVERFLOW:
                                int appSize = sslEngine.getSession().getApplicationBufferSize();
                                if (appSize > outAppData.capacity()) {
                                    ByteBuffer buffer = ByteBuffer.allocate(appSize);
                                    outAppData.flip();
                                    buffer.put(outAppData);
                                    outAppData = buffer;
                                    outAppData.flip();
                                }


                                int netSize = sslEngine.getSession().getPacketBufferSize();
                                if (netSize > outNetData.capacity()) {
                                    //enlarge the peer network packet buffer
                                    ByteBuffer buffer = ByteBuffer.allocate(netSize);
                                    //buffer.put(outNetData);
                                    outNetData = buffer;
                                    //outNetData.flip();
                                    //System.out.println("When Buffer Underflow");
                                }

                                break;
                            default:
                                return -1;
                        }
                    }
                }
            }

        }

        return -1;
    }

    protected void setEndpoint(SocketAddress endpoint) {
        _endpoint = endpoint;
    }

    //Verifica constantemente o status do handshake para algum tratamento
    private class HandshakeHandler extends Thread {

        private boolean firstHandshake = true;
        private byte[]  inData = new byte[65535];

        @Override
        public void run() {
            handshakeLock.lock();
            SSLEngineResult.HandshakeStatus hs = sslEngine.getHandshakeStatus();

            try {
                while (hs != SSLEngineResult.HandshakeStatus.FINISHED && hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                    switch (hs) {
                        case NEED_UNWRAP:
                            if (_inSeqRecvQueue.isEmpty())
                                break;
                            int readedBytes = SecureReliableSocket.super.read(inData, 0, 65535);
                            if (readedBytes < 0)
                                break;
                            inNetData.put(inData,0,readedBytes);
                            inNetData.flip();
                            /*inNetData.position(0);
                            inNetData.limit(readedBytes);*/
                        case NEED_UNWRAP_AGAIN:
                            SSLEngineResult res = sslEngine.unwrap(inNetData, inAppData);
                            inNetData.compact();
                            System.out.println("Fez o unwrap: "+res.getStatus());

                            switch (res.getStatus()) {
                                case OK:
                                    inNetData.clear();
                                    break;
                                case CLOSED:
                                    //UdpCommon.whenSSLClosed();
                                    break;
                                case BUFFER_OVERFLOW:
                                    int appSize = sslEngine.getSession().getApplicationBufferSize();
                                    if (appSize > inAppData.capacity()) {
                                        ByteBuffer buffer = ByteBuffer.allocate(appSize);
                                        buffer.put(inAppData);
                                        inAppData = buffer;
                                    }
                                    break;
                                case BUFFER_UNDERFLOW:
                                    System.out.println("Buffer underflow wrap");
                                    break;
                            }
                            break;
                        case NEED_WRAP:
                            outNetData.clear();
                            res = sslEngine.wrap(outAppData, outNetData);
                            System.out.println("Fez o wrap");
                            switch (res.getStatus()) {
                                case OK:
                                    outNetData.flip();
                                    SecureReliableSocket.super.write(outNetData.array(), outNetData.arrayOffset(), outNetData.limit());
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
            } catch (IOException e) {
                e.printStackTrace();
            } catch (BufferOverflowException e)
            {
                e.printStackTrace();
            }
            finally {
                hasHandshake.signalAll();
                handshakeLock.unlock();
            }
        }
    }
}
