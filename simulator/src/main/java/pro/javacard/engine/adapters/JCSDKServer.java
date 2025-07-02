package pro.javacard.engine.adapters;

import com.licel.jcardsim.base.Simulator;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.engine.core.JavaCardEngine;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

public class JCSDKServer extends AbstractTCPAdapter {
    // Protocol: clients (like PC/SC adapter or javax.smartcardio library)
    // connect to us.
    // Protocol: uint32 followed with payload.
    // Command messages in high byte: 0xFE power down, 0xF0 send ATR
    // 0x00 messages encode length of APDU-s
    private static final Logger log = LoggerFactory.getLogger(JCSDKServer.class);

    public static final int DEFAULT_JCSDK_PORT = 9025;
    public static final String DEFAULT_JCSDK_HOST = "0.0.0.0";

    static ByteBuffer format(byte code, byte[] data) {
        ByteBuffer buffer = ByteBuffer.allocate(4 + data.length);
        buffer.putInt(data.length);
        buffer.put(0, code);
        buffer.position(4);
        buffer.put(data);
        buffer.rewind();
        log.info(Hex.toHexString(buffer.array()));
        return buffer;
    }

    ServerSocketChannel server;

    public JCSDKServer(String host, int port, JavaCardEngine sim) {
        super(host, port, sim);
    }

    @Override
    public void start() throws IOException {
        server = start(host, port);
    }

    @Override
    public RemoteMessage recv(SocketChannel channel) throws IOException {
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
                return new RemoteMessage(RemoteMessage.Type.ATR);
            case (byte) 0xFE:
                return new RemoteMessage(RemoteMessage.Type.POWERDOWN);
            case 0x00:
                int cmdlen = hdr.getInt(0);
                ByteBuffer cmd = ByteBuffer.allocate(cmdlen);
                channel.read(cmd);
                return new RemoteMessage(RemoteMessage.Type.APDU, cmd.array());
            default:
                throw new IOException("Unknown command header: %s" + Hex.toHexString(hdr.array()));
        }
    }

    @Override
    public void send(SocketChannel channel, RemoteMessage message) throws IOException {
        log.info("Sending " + message.getType());
        switch (message.getType()) {
            case APDU:
                channel.write(format((byte) 0x00, message.getPayload()));
                break;
            case ATR:
                channel.write(format((byte) 0xF0, atr == null ? message.getPayload() : atr));
                break;
            case POWERDOWN:
                //channel.close();
                // Do nothing
                break;
            default:
                log.warn("Unknown message for protocol: " + message.getType());
        }
    }

    @Override
    public SocketChannel getSocket() throws IOException {
        return server.accept();
    }
}
