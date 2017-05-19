package leopoldino.smrudp;

import net.rudp.impl.Segment;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

/**
 * Adapted AsyncScheduler for work with SecureSocket
 */
public class NioScheduler implements Runnable {

    /**
     * Logger
     */
    public static final Logger LOGGER = Logger.getLogger(NioScheduler.class.getCanonicalName());
    /**
     * Singleton Instance.
     */
    private static NioScheduler scheduler = new NioScheduler();
    /**
     * Socket Selector.
     */
    protected volatile Selector selector;
    /**
     * Selector Lock.
     */
    protected ReentrantLock selectorLock;
    /**
     * Receive Buffer.
     */
    protected ByteBuffer recvBuffer;
    /**
     * The received segments buffer for the Producer/Consumer mechanism.
     */
    private BlockingQueue<BufferedPacket> receivedSegments;

    /**
     * The received segments buffer for the Producer/Consumer mechanism.
     */
    private BlockingQueue<QueuedPacket> queuedSegments;

    /**
     * The receiving and processing Thread.
     */
    private ReceiveThread receiveThread;

    /**
     * The receiving and processing Thread.
     */
    private SendThread sendThread;

    /**
     * Singleton Private Constructor.
     */
    protected NioScheduler() {
        try {
            this.selector = Selector.open();
            this.selectorLock = new ReentrantLock();
            this.recvBuffer = ByteBuffer.allocate(65535);
            this.receivedSegments = new ArrayBlockingQueue<BufferedPacket>(1024 * 10);
            this.queuedSegments = new ArrayBlockingQueue<QueuedPacket>(1024 * 10);
            this.receiveThread = new ReceiveThread();
            this.sendThread = new SendThread();

            // Start Receiving/Writting Thread.
            this.sendThread.start();
            this.receiveThread.start();
            new Thread(this, "NioScheduler").start();
        } catch (IOException e) {
            System.err.println("Could not create Scheduler.");
            System.exit(-1);
        }
    }

    /**
     * Entry-Point to the scheduler.
     */
    public static NioScheduler getNioScheduler() {
        return scheduler;
    }

    /**
     * Register a channel to a socket.
     */
    public SelectionKey register(DatagramChannel channel, SecureReliableSocket socket) {
        SelectionKey key = null;
        selectorLock.lock();
        try {
            channel.configureBlocking(false);
            selector.wakeup();
            key = channel.register(selector, SelectionKey.OP_READ);
            key.attach(socket);
        } catch (Exception e) {
            LOGGER.severe("COULD NOT REGISTER CHANNEL");
        } finally {
            selectorLock.unlock();
        }

        return key;
    }

    /**
     * Receiving Segment Routine.
     */
    @Override
    public void run() {
        // Declaring variables here to reuse.
        Segment segment;
        SelectionKey key;
        Set<SelectionKey> selectedKeys;
        Iterator<SelectionKey> keyIterator;
        byte[] buf = null;
        int tot = -1;
        BufferedPacket bufferedPacket = null;
        SecureReliableSocket socket;

        // Scheduler Main Loop
        while (true) {
            try {
                selector.select();
                selectedKeys = selector.selectedKeys();

                //Solve a deadlock caused by register
                selectorLock.lock();
                selectorLock.unlock();

                keyIterator = selectedKeys.iterator();

                while (keyIterator.hasNext()) {
                    key = keyIterator.next();
                    socket = (SecureReliableSocket) key.attachment();
                    recvBuffer.clear();
                    socket._lastEndpoint = ((DatagramChannel) key.channel()).receive(recvBuffer);
                    tot = recvBuffer.position();
                    buf = new byte[tot];
                    System.arraycopy(recvBuffer.array(), 0, buf, 0, buf.length);
                    bufferedPacket = new BufferedPacket(buf, socket);
                    receivedSegments.put(bufferedPacket);

                    keyIterator.remove();
                }
            } catch (IOException e) {
                LOGGER.warning("IO error on receive routine");
                e.printStackTrace();
            } catch (InterruptedException e) {
                LOGGER.warning("Sync error on receive routine");
                e.printStackTrace();
            }
        }
    }

    /**
     * Writting Segment Routine.
     */
    public void submit(DatagramChannel channel, SocketAddress endpoint, byte[] buffer, int off, int len) {
        try {
            QueuedPacket packet = new QueuedPacket(channel, endpoint, buffer, off, len);
            queuedSegments.put(packet);
        } catch (Exception ex) {
            LOGGER.severe("Error at submitting Segment");
            ex.printStackTrace();
        }
    }

    /**
     * ThreadFactory.
     */
    public static class ScheduleFactory implements ThreadFactory {
        private String name;
        private int counter;

        public ScheduleFactory(String name) {
            this.counter = 1;
            this.name = name;
        }

        @Override
        public Thread newThread(Runnable r) {
            return new Thread(r, name + "-" + counter++);
        }
    }

    /**
     * Routine class to dispatch the Selector's received packages.
     */
    protected class ReceiveThread extends Thread {
        private SecureReliableSocket socket;

        @Override
        public void run() {
            BufferedPacket packet = null;
            while (true) {
                try {
                    packet = receivedSegments.take();
                    socket = packet.getSecureReliableSocket();
                    socket.receiveRawData(packet.getBuffer(), 0, packet.getBuffer().length);
                } catch (InterruptedException e) {
                    LOGGER.severe("Problem at reading buffer. Interrupted.");
                    e.printStackTrace();
                } catch (Exception ex) {
                    LOGGER.severe("Problem at parsing Segment received. Pkg received is corrupted.");
                    ex.printStackTrace();
                }
            }
        }
    }

    /**
     * Routine class to dispatch the Selector's received packages.
     */
    protected class SendThread extends Thread {

        @Override
        public void run() {
            QueuedPacket packet = null;
            while (true) {
                try {
                    packet = queuedSegments.take();
                    packet.getChannel().send(
                            ByteBuffer.wrap(packet.getBuffer(),
                                    packet.getOffset(),
                                    packet.getLength()),
                            packet.getEndpoint());
                } catch (InterruptedException e) {
                    LOGGER.severe("Problem at reading buffer. Interrupted.");
                    e.printStackTrace();
                } catch (Exception ex) {
                    LOGGER.severe("Problem at parsing Segment received. Pkg received is corrupted.");
                    ex.printStackTrace();
                }
            }
        }
    }

    /**
     * Just a bean class carrying the bytes received from an endpoint.
     *
     * @author lincoln
     */
    private class BufferedPacket {
        private byte[] buf;
        private SecureReliableSocket sock;

        public BufferedPacket(byte[] buffer, SecureReliableSocket sock) {
            this.buf = buffer;
            this.sock = sock;
        }

        public byte[] getBuffer() {
            return buf;
        }

        public SecureReliableSocket getSecureReliableSocket() {
            return sock;
        }

    }

    /**
     * Just a bean class carrying the bytes to be send to an endpoint.
     *
     * @author lincoln
     */
    private class QueuedPacket {
        private DatagramChannel channel;
        private SocketAddress endpoint;
        private byte[] buffer;
        private int offset;
        private int length;

        public QueuedPacket(DatagramChannel channel, SocketAddress endpoint, byte[] buffer, int offset, int length) {
            this.channel = channel;
            this.endpoint = endpoint;
            this.buffer = buffer;
            this.offset = offset;
            this.length = length;
        }

        public DatagramChannel getChannel() {
            return channel;
        }

        public SocketAddress getEndpoint() {
            return endpoint;
        }

        public byte[] getBuffer() {
            return buffer;
        }

        public int getOffset() {
            return offset;
        }

        public int getLength() {
            return length;
        }
    }

}