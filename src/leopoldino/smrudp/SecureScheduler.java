package leopoldino.smrudp;

import net.rudp.ReliableSocket;
import net.rudp.impl.Segment;
import org.bouncycastle.crypto.tls.DTLSTransport;

import java.io.IOException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.util.Iterator;
import java.util.Set;

/**
 * This is a improvised implementation of Input/output scheduler for SecureReliableSocket.
 * It works fine, but is not a perfect implementation, because of the limitations of DTLS
 * Bouncy Castle implementation (the lack of implementation with the NIO API).
 *
 * @author Gabriel Leopoldino
 */
public class SecureScheduler extends net.rudp.AsyncScheduler {

    private static SecureScheduler _secureScheduler = new SecureScheduler();

    public static SecureScheduler getSecureScheduler() {
        return _secureScheduler;
    }

    public SelectionKey register(DatagramChannel channel, ReliableSocket socket, DTLSTransport transport) {
        SelectionKey key = null;
        selectorLock.lock();
        try {
            channel.configureBlocking(false);
            selector.wakeup();
            key = channel.register(selector, SelectionKey.OP_READ);
            key.attach(new Attacher(socket, transport));
        } catch (Exception e) {
            LOGGER.severe("COULD NOT REGISTER CHANNEL");
        } finally {
            selectorLock.unlock();
        }

        return key;
    }

    @Override
    public void run() {
        // Declaring variables here to reuse.
        Segment segment;
        SelectionKey key;
        Set<SelectionKey> selectedKeys;
        Iterator<SelectionKey> keyIterator;
        Attacher attacher;
        int length;

        // Scheduler Main Loop
        while (true) {
            try {
                selector.select();
                selectedKeys = selector.selectedKeys();

                selectorLock.lock();
                selectorLock.unlock();

                keyIterator = selectedKeys.iterator();

                while (keyIterator.hasNext()) {
                    key = keyIterator.next();

                    attacher = (Attacher) key.attachment();
                    length = attacher.getTransport().receive(recvBuffer.array(), 0, recvBuffer.capacity(), 0);

                    recvBuffer.flip();
                    try {
                        segment = Segment.parse(recvBuffer.array(), 0, length);
                        recvThreadPool.submit(new ReceiveTask(attacher.getSocket(), segment));
                    } catch (Exception ex) {
                        LOGGER.severe("Problem at parsing Segment received. Pkg received is corrupted.");
                    } finally {
                        recvBuffer.clear();
                    }
                    keyIterator.remove();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void submit(DTLSTransport secureTransport, Segment segment) {
        try {
            sendSemaphore.acquire();
            secureTransport.send(segment.getBytes(), 0, segment.length());
        } catch (Exception ex) {
            LOGGER.severe("Error at submitting Segment");
            ex.printStackTrace();
        } finally {
            sendSemaphore.release();
        }
    }

    private class Attacher {
        private ReliableSocket socket;
        private DTLSTransport transport;

        public Attacher(ReliableSocket socket) {
            this.socket = socket;
        }

        public Attacher(ReliableSocket socket, DTLSTransport transport) {
            this.socket = socket;
            this.transport = transport;
        }

        public ReliableSocket getSocket() {
            return socket;
        }

        public void setSocket(ReliableSocket socket) {
            this.socket = socket;
        }

        public DTLSTransport getTransport() {
            return transport;
        }

        public void setTransport(DTLSTransport transport) {
            this.transport = transport;
        }
    }
}
