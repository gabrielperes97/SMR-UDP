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
    protected Lock outputLock;
    protected Lock inputLock;

    protected SSLEngine sslEngine;
    protected SecurityProfile securityProfile;
    protected List<SecureReliableSocketStateListener> secureStateListeners;
    protected byte[] inData;


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
        this.inputLock = new ReentrantLock();
        this.outputLock = new ReentrantLock();

        this.inData = new byte[(_profile.maxSegmentSize() - Segment.RUDP_HEADER_LEN) * _profile.maxRecvQueueSize()];

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
        super.connect(endpoint, timeout);
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
    public synchronized void close() throws IOException {
        outputLock.lock();
        inputLock.lock();

        sslEngine.closeOutbound();
        outAppData.clear();
        while (!sslEngine.isOutboundDone())
        {
            outNetData.clear();
            SSLEngineResult res = sslEngine.wrap(outAppData, outNetData);
            outNetData.flip();
            rawWrite(outNetData.array(), 0, outNetData.limit());

        }
        super.close();
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

    protected synchronized int rawWrite(byte[] b, int off, int len) throws IOException
    {
        return super.write(b, off, len);
    }

    protected synchronized int rawRead(byte[] b, int off, int len) throws IOException
    {
        return super.read(b, off, len);
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
        }
        int lenFinalArray = 0;

        inputLock.lock();
        int i = super.read(inData, 0, inData.length);
        if (i > 0) {
            inNetData.clear();
            inNetData.put(inData, 0, i);
            inNetData.flip();
            inAppData.clear();

            SSLEngineResult res = null;
            while (res == null || res.getStatus() != SSLEngineResult.Status.OK || inNetData.hasRemaining()) {
                res = sslEngine.unwrap(inNetData, inAppData);
                switch (res.getStatus()) {
                    case BUFFER_OVERFLOW:
                        int appSize = sslEngine.getSession().getApplicationBufferSize();
                        if (appSize > inAppData.capacity()) {
                            ByteBuffer buffer = ByteBuffer.allocate(appSize);
                            buffer.put(inAppData);
                            inAppData = buffer;
                        }
                        break;
                    case BUFFER_UNDERFLOW:
                        inNetData.compact();
                        i = super.read(inNetData.array(), 0, inData.length);
                        inNetData.put(inData, 0, i);
                        inNetData.flip();
                        break;
                    case CLOSED:
                        inputLock.unlock();
                        return -1;
                    case OK:
                        lenFinalArray += res.bytesProduced();
                        break;
                }
            }
            System.arraycopy(inAppData.array(), inAppData.arrayOffset(), b, off, lenFinalArray);
        }
        else {
            inputLock.unlock();
            return -1;
        }
        inputLock.unlock();
        if (lenFinalArray > 0)
            return lenFinalArray;
        else
            return read(b, off, len);
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
        }

        outputLock.lock();

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
                        int i = super.write(outNetData.array(), outNetData.arrayOffset(), res.bytesProduced());
                        outputLock.unlock();
                        return i;
                    case BUFFER_OVERFLOW:
                        int appSize = sslEngine.getSession().getApplicationBufferSize();
                        if (appSize > outAppData.capacity())
                        {
                            ByteBuffer buffer = ByteBuffer.allocate(appSize);
                            outAppData.flip();
                            buffer.put(outAppData);
                            outAppData = buffer;
                        }


                        int netSize = sslEngine.getSession().getPacketBufferSize();
                        if(netSize > outNetData.capacity())
                        {
                            //enlarge the peer network packet buffer
                            ByteBuffer buffer = ByteBuffer.allocate(netSize);
                            outNetData.flip();
                            buffer.put(outNetData);
                            outNetData = buffer;
                        }

                        break;
                    default:
                        outputLock.unlock();
                        return -1;
                }
            }
        }
        outputLock.unlock();
        return -1;
    }

    protected void setEndpoint(SocketAddress endpoint) {
        _endpoint = endpoint;
    }

    //Verifica constantemente o status do handshake para algum tratamento
    private class HandshakeHandler extends Thread {

        private boolean firstHandshake = true;

        @Override
        public void run() {
            handshakeLock.lock();
            SSLEngineResult.HandshakeStatus hs = sslEngine.getHandshakeStatus();

            try {
                while (hs != SSLEngineResult.HandshakeStatus.FINISHED && hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                    switch (hs) {
                        case NEED_UNWRAP:
                            int readedBytes = 0;
                            if (!_inSeqRecvQueue.isEmpty())
                                readedBytes = rawRead(inData, 0, 65535);
                            inNetData.put(inData,0,readedBytes);
                            inNetData.flip();
                        case NEED_UNWRAP_AGAIN:
                            SSLEngineResult res = sslEngine.unwrap(inNetData, inAppData);
                            inNetData.compact();

                            switch (res.getStatus()) {
                                case OK:
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
                                    break;
                            }
                            break;
                        case NEED_WRAP:
                            outNetData.clear();
                            res = sslEngine.wrap(outAppData, outNetData);
                            switch (res.getStatus()) {
                                case OK:
                                    outNetData.flip();
                                    rawWrite(outNetData.array(), outNetData.arrayOffset(), outNetData.limit());
                                    break;
                                case CLOSED:
                                    break;
                                case BUFFER_OVERFLOW:
                                    int appSize = sslEngine.getSession().getApplicationBufferSize();
                                    if (appSize > outAppData.capacity()) {
                                        ByteBuffer b = ByteBuffer.allocate(appSize);
                                        b.put(outAppData);
                                        outAppData = b;
                                    }


                                    int netSize = sslEngine.getSession().getPacketBufferSize();
                                    if (netSize > outNetData.capacity()) {
                                        ByteBuffer b = ByteBuffer.allocate(netSize);
                                        b.put(outNetData);
                                        outNetData = b;
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
