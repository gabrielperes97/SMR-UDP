/*
 * TeleStax, Open Source Cloud Communications
 * Copyright 2011-2014, Telestax Inc and individual contributors
 * by the @authors tag.
 *
 * This program is free software: you can redistribute it and/or modify
 * under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

package leopoldino.smrudp.impl;

import org.bouncycastle.crypto.tls.DatagramTransport;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

/**
 * Datagram Transport implementation that uses NIO instead of bocking IO.
 *
 * @author Gabriel Leopoldino
 */
public class NioUdpTransport implements DatagramTransport {

    protected final DatagramChannel channel;
    private final int receiveLimit;
    private final int sendLimit;
    protected SocketAddress endpoint;
    protected SocketAddress lastRcvAddress;

    public NioUdpTransport(DatagramChannel channel, int receiveLimit, int sendLimit) {
        this.channel = channel;
        this.receiveLimit = receiveLimit;
        this.sendLimit = sendLimit;
    }

    public NioUdpTransport(DatagramChannel channel, int receiveLimit, int sendLimit, SocketAddress endpoint) {
        this.channel = channel;
        this.endpoint = endpoint;
        this.receiveLimit = receiveLimit;
        this.sendLimit = sendLimit;
    }

    @Override
    public int getReceiveLimit() throws IOException {
        return this.receiveLimit;
    }

    @Override
    public int getSendLimit() throws IOException {
        return this.sendLimit;
    }

    public SocketAddress getEndpoint() {
        return endpoint;
    }

    public void setEndpoint(SocketAddress endpoint) {
        this.endpoint = endpoint;
    }

    @Override
    public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(buf, off, len);
        lastRcvAddress = this.channel.receive(buffer);
        if (endpoint == null)
            endpoint = lastRcvAddress;
        return buffer.limit(); //retornar tamanho recebido
    }

    @Override
    public void send(byte[] buf, int off, int len) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(buf, off, len);
        channel.send(buffer, endpoint);
    }

    @Override
    public void close() throws IOException {

    }

}
