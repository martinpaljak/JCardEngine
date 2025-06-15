package pro.javacard.jcardsim.tool;

import com.licel.jcardsim.base.CardInterface;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

public class JCSDKServer extends RemoteTerminalProtocol {
    // Protocol: clients (like PC/SC adapter or javax.smartcardio library)
    // connect to us.
    // Protocol: uint32 followed with payload.
    // Command messages in high byte: 0xFE power down, 0xF0 send ATR
    // 0x00 messages encode length of APDU-s
    private static final Logger log = LoggerFactory.getLogger(JCSDKServer.class);

    static byte[] ATR_SDK = Hex.decode("3B9F968131FE454F52434C2D4A43332E324750322E3323");
    public static int DEFAULT_SDK_PORT = 9025;

    private static ByteBuffer format(byte code, byte[] data) {
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
    final int port;

    public JCSDKServer(int port, CardInterface sim) {
        super(sim);
        this.port = port;
    }

    @Override
    public void start() throws IOException {
        server = RemoteTerminalProtocol.start("0.0.0.0", port);
    }

    @Override
    public RemoteMessage recv(SocketChannel channel) throws IOException {
        log.trace("Trying to read header ...");
        ByteBuffer hdr = ByteBuffer.allocate(4);
        int len = channel.read(hdr);
        if (len < 0) {
            log.info("client closed connection");
            throw new EOFException("Client closed connection");
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
        log.info("Sending " + message.type);
        switch (message.type) {
            case APDU:
                channel.write(format((byte) 0x00, message.payload));
                break;
            case ATR:
                channel.write(format((byte) 0xF0, message.payload));
                break;
            case POWERDOWN:
                //channel.close();
                // Do nothing
                break;
            default:
                log.warn("Unknown message for protocol: " + message.type);
        }
    }

    @Override
    public SocketChannel getSocket() throws IOException {
        return server.accept();
    }
}
