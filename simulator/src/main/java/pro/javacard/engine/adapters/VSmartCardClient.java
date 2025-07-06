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
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.function.Supplier;

public final class VSmartCardClient extends AbstractTCPAdapter {
    private static final Logger log = LoggerFactory.getLogger(VSmartCardClient.class);

    // Default values
    public static final int DEFAULT_VSMARTCARD_PORT = 35963;
    public static final String DEFAULT_VSMARTCARD_HOST = "127.0.0.1";

    int port = DEFAULT_VSMARTCARD_PORT;
    String host = DEFAULT_VSMARTCARD_HOST;

    // Protocol:
    // We are a client, connecting to vpcd server
    // Server initiates messaging, to which we answer
    // messages are uint16, followed with payload
    // command messages are of length 1, where commands are:
    // 0x00 - power off (no response)
    // 0x01 - power on (no response)
    // 0x02 - reset (no response)
    // 0x04 - get ATR . replied with 0xXXYY length + atr
    // Everything else - command APDU, followed with response APDU.
    // See https://frankmorgner.github.io/vsmartcard/virtualsmartcard/api.html#creating-a-virtual-smart-card
    public VSmartCardClient(Supplier<EngineSession> sim) {
        super(sim);
    }

    static ByteBuffer _send(byte[] data) throws IOException {
        if (data.length > Short.MAX_VALUE)
            throw new IllegalArgumentException("Too big payload");
        ByteBuffer payload = ByteBuffer.allocate(2 + data.length);
        payload.putShort((short) data.length);
        payload.put(data);
        payload.rewind();
        return payload;
    }

    @Override
    protected void send(SocketChannel channel, RemoteMessage message) throws IOException {
        log.trace("Sending {}", message.getType());
        ByteBuffer msg;
        switch (message.getType()) {
            case ATR:
                msg = _send(atr);
                break;
            case APDU:
                msg = _send(message.getPayload());
                break;
            default:
                log.trace("Trying to send ignored message: " + message.getType());
                return;
        }
        log.trace("Sending {}", Hex.toHexString(msg.array()));
        channel.write(msg);
    }

    @Override
    protected SocketChannel getSocket() throws IOException {
        return AbstractTCPAdapter.connect(host, port);
    }

    ByteBuffer _read(SocketChannel channel, int len) throws IOException {
        log.trace("Waiting for input ...");
        ByteBuffer buf = ByteBuffer.allocate(len);
        int read = channel.read(buf);
        if (read == -1) {
            throw new EOFException("Peer is gone");
        }
        if (read != len) {
            throw new IOException("Could not read buffer: " + read);
        }
        buf.rewind();
        return buf;
    }

    @Override
    protected RemoteMessage recv(SocketChannel channel) throws IOException {
        ByteBuffer hdr = _read(channel, 2);

        short len = hdr.getShort(0);
        if (len < 0) {
            throw new IOException("Received unexpected length: " + len);
        }

        // command
        if (len == 0x01) {
            ByteBuffer cmd = _read(channel, 1);
            switch (cmd.get(0)) {
                case 0x00: // power off;
                    return new RemoteMessage(RemoteMessage.Type.POWERDOWN);
                case 0x01: // power on;
                    return new RemoteMessage(RemoteMessage.Type.POWERUP);
                case 0x02: // reset;
                    return new RemoteMessage(RemoteMessage.Type.RESET);
                case 0x04: // ATR
                    return new RemoteMessage(RemoteMessage.Type.ATR);
                default:
                    throw new IOException("Received unknown command: " + cmd);
            }
        }
        // APDU otherwise
        ByteBuffer apdu = _read(channel, len);
        return new RemoteMessage(RemoteMessage.Type.APDU, apdu.array());
    }
}
