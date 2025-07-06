/*
 * Copyright 2025 Martin Paljak
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package pro.javacard.engine.adapters;

import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.engine.EngineSession;

import java.io.EOFException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.function.Supplier;

// Reverse of the server
public class JCSDKClient implements Supplier<EngineSession>, EngineSession {
    private static final Logger log = LoggerFactory.getLogger(JCSDKClient.class);

    final String host;
    final int port;
    private SocketChannel channel;
    private byte[] atr;

    private boolean closed;

    public JCSDKClient(String host, int port) {
        this.port = port;
        this.host = host;
    }

    static RemoteMessage recv(SocketChannel channel) throws IOException {
        log.trace("Trying to read header ...");
        ByteBuffer hdr = ByteBuffer.allocate(4);
        int len = channel.read(hdr);
        if (len < 0) {
            log.info("Peer closed connection");
            throw new EOFException("Peer closed connection");
        }
        byte b1 = hdr.get(0);
        log.info("Received {}", Hex.toHexString(hdr.array()));
        switch (b1) {
            case (byte) 0xF0:
                int atrlen = hdr.getShort(2);
                ByteBuffer atr = ByteBuffer.allocate(atrlen);
                channel.read(atr);
                return new RemoteMessage(RemoteMessage.Type.ATR, atr.array());
            case 0x00:
                int cmdlen = hdr.getInt(0);
                ByteBuffer cmd = ByteBuffer.allocate(cmdlen);
                do {
                    channel.read(cmd);
                    log.trace("Read {} out of {}", cmd.position(), cmd.limit());
                } while (cmd.position() < cmd.limit());
                return new RemoteMessage(RemoteMessage.Type.APDU, cmd.array());
            default:
                throw new IOException("Unknown command header: %s" + Hex.toHexString(hdr.array()));
        }
    }

    static RemoteMessage send(SocketChannel channel, RemoteMessage message) throws IOException {
        log.info("Sending " + message.getType());
        switch (message.getType()) {
            case APDU:
                channel.write(JCSDKServer.format((byte) 0x00, message.getPayload()));
                break;
            case ATR:
                channel.write(JCSDKServer.format((byte) 0xF0, new byte[0]));
                break;
            case POWERDOWN:
                channel.write(JCSDKServer.format((byte) 0xFE, new byte[0]));
                channel.close();
                // Server also closes connection after it.
                return null;
            default:
                log.warn("Unknown message for protocol: " + message.getType());
        }
        RemoteMessage received = recv(channel);
        log.trace("Received {}: {}", received.getType(), Hex.toHexString(received.getPayload()));
        return received;
    }

    public SocketChannel getSocket() throws IOException {
        return AbstractTCPAdapter.connect(host, port);
    }

    @Override
    public void reset() {
        // Deprecated
        try {
            send(this.channel, new RemoteMessage(RemoteMessage.Type.POWERDOWN));
            this.atr = send(this.channel, new RemoteMessage(RemoteMessage.Type.ATR)).getPayload();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public byte[] getATR() {
        if (this.atr == null) {
            reset();
        }
        return this.atr.clone();
    }

    @Override
    public byte[] transmitCommand(byte[] commandAPDU) {
        try {
            return send(this.channel, new RemoteMessage(RemoteMessage.Type.APDU, commandAPDU)).getPayload();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public String getProtocol() {
        return "T=1"; // FIXME
    }

    @Override
    public EngineSession get() {
        try {
            JCSDKClient connection = new JCSDKClient(host, port);
            connection.channel = AbstractTCPAdapter.connect(host, port);
            connection.atr = send(connection.channel, new RemoteMessage(RemoteMessage.Type.ATR)).getPayload();
            return connection;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void close(boolean reset) {
        log.trace("Closing connection");
        try {
            if (reset) {
                send(this.channel, new RemoteMessage(RemoteMessage.Type.POWERDOWN));
            }
            closed = true;
            this.channel.close();
        } catch (IOException e) {
            log.error("Could not send POWERDOWN", e);
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public boolean isClosed() {
        return closed;
    }
}
