package pro.javacard.jcardsim.tool;

import com.licel.jcardsim.base.CardInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

public class VSmartCard extends RemoteTerminalProtocol {
    private static final Logger log = LoggerFactory.getLogger(VSmartCard.class);

    // Protocol:
    // We are a client, connecting to vpcd server
    // Server initiates communication, to which we answer
    // messages are uint16, followed with payload
    // command messages are of length 1, where commands are:
    // 0x00 - power off (no response)
    // 0x01 - power on (no response)
    // 0x02 - reset (no response)
    // 0x04 - get ATR . replied with 0xXXYY length + atr
    // Everything else - command APDU, followed with response APDU.
    // See https://frankmorgner.github.io/vsmartcard/virtualsmartcard/api.html#creating-a-virtual-smart-card

    final String host;
    final int port;

    public VSmartCard(String host, Integer port, CardInterface sim) {
        super(sim);
        this.host = host;
        this.port = port;
    }

    static int code(SocketChannel channel) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(2);
        int len = channel.read(buffer);
        if (len == -1) {
            throw new EOFException("Client gone");
        }
        short c = buffer.getShort();
        if (c < 0)
            throw new IOException("Unexpected length: " + c);
        return c;
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
    public void send(SocketChannel channel, RemoteMessage message) throws IOException {
        switch (message.type) {
            case ATR:
                _send(message.payload);
                break;
            case APDU:
                _send(message.payload);
                break;
            default:
                log.warn("Unknown/ignored message for protocol: " + message.type);
        }
    }

    @Override
    public SocketChannel getSocket() throws IOException {
        return RemoteTerminalProtocol.connect(host, port);
    }

    @Override
    public RemoteMessage recv(SocketChannel channel) throws IOException {
        int c = code(channel);
        switch (c) {
            case 0x00: // power off;
                return new RemoteMessage(RemoteMessage.Type.POWERDOWN);
            case 0x01: // power on;
                return new RemoteMessage(RemoteMessage.Type.POWERUP);
            case 0x02: // reset;
                return new RemoteMessage(RemoteMessage.Type.RESET);
            case 0x04: // ATR
                return new RemoteMessage(RemoteMessage.Type.ATR);
            default: // APDU
                ByteBuffer apdu = ByteBuffer.allocate(c);
                channel.read(apdu);
                return new RemoteMessage(RemoteMessage.Type.APDU, apdu.array());
        }
    }
}
