package leopoldino.smrudp;

import net.rudp.AsyncScheduler;
import net.rudp.ReliableSocket;
import net.rudp.impl.Segment;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

/**
 * This is a very fu#####ing cool implementation of Input/output scheduler for SecureReliableSocket.
 * It works fine, and it's much better than my lasts versions.
 *
 * @author Gabriel Leopoldino
 */
public class SecureScheduler extends AsyncScheduler {

    private static SecureScheduler _secureScheduler = new SecureScheduler();

    public static SecureScheduler getSecureScheduler() {
        return _secureScheduler;
    }

    public SelectionKey register(DatagramChannel channel, ReliableSocket socket) {
        SelectionKey key = null;
        super.selectorLock.lock();
        try {
            channel.configureBlocking(false);
            super.selector.wakeup();
            key = channel.register(super.selector, SelectionKey.OP_READ);
            key.attach(socket);
        } catch (Exception e) {
            LOGGER.severe("COULD NOT REGISTER CHANNEL");
        } finally {
            super.selectorLock.unlock();
        }
        System.out.println("Registred");
        return key;
    }

    /**
     * Receiving packets from DatagramChannel
     * We receive the packet from the internet, give this to socket and it works with it
     */
    
    @Override
    public void run()
    {
        while (true)
        {
            try
            {
                super.selector.select();
                Iterator selectedKeys = super.selector.selectedKeys().iterator();

                super.selectorLock.lock();
                super.selectorLock.unlock();


                while(selectedKeys.hasNext())
                {
                    SelectionKey key = (SelectionKey) selectedKeys.next();
                    selectedKeys.remove();

                    if (!key.isValid())
                        continue;

                    if (key.isReadable())
                    {
                        SecureReliableSocket client = (SecureReliableSocket) key.attachment();

                        //I can't guarantee that the client can work with the package until it receive more packets
                        //so I allocate temporary buffers here.
                        //It's better than I copy the data two times.
                        ByteBuffer inputData = ByteBuffer.allocate(client.getNetBufferSize());
                        SocketAddress addr = ((DatagramChannel) key.channel()).receive(inputData);
                        //inputData.flip();
                        super.recvThreadPool.submit(new ReceiveTask(client, inputData, addr));
                    }
                }
            } catch (IOException e) {
                LOGGER.warning("IO error on receive routine");
                e.printStackTrace();
            }
        }
    }

    /**
     * Sending packets through DatagramChannel
     *
     * We don't need a lock for use send method because the Java Documentation says this.
     *
     * " This method may be invoked at any time. If another thread has already initiated a write operation upon this
     *  channel, however, then an invocation of this method will block until the first operation is complete.
     *  If this channel's socket is not bound then this method will first cause the socket to be bound to an address
     *  that is assigned automatically, as if by invoking the bind method with a parameter of null. "
     *
     *  https://docs.oracle.com/javase/7/docs/api/java/nio/channels/DatagramChannel.html#send(java.nio.ByteBuffer,%20java.net.SocketAddress)
     *
     */
    public void submit(DatagramChannel channel, SocketAddress endpoint, ByteBuffer outputData) {
        try {
            while (outputData.hasRemaining()) {
                channel.send(outputData, endpoint);
            }
        }
        catch (Exception ex) {
            LOGGER.severe("Error at submitting Segment");
            ex.printStackTrace();
        }
    }

    /**
     * This task exists because the ConcurrentLinkedQueue, used in receiveRawData, can block the Thread until the data is
     * inserted in the list, and we don't want this on the receiving server thread.
     */
    class ReceiveTask implements Runnable
    {
        private SecureReliableSocket socket;
        private ByteBuffer data;
        private SocketAddress addr;

        public ReceiveTask(SecureReliableSocket socket, ByteBuffer data, SocketAddress addr) {
            this.socket = socket;
            this.data = data;
            this.addr = addr;
        }

        @Override
        public void run() {
            Segment segment = Segment.tryParse(this.data.array(), 0, this.data.position());
            if (segment == null)
                //this.socket.receiveRawData(this.data);
                LOGGER.warning("Cannot parse data");
            else
                this.socket.scheduleReceive(segment);
        }
    }


}
