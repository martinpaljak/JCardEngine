package pro.javacard.jcardsim.adapters;

import com.licel.jcardsim.base.CardInterface;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

// Reverse of the server
public class JCSDKClient implements CardInterface {
    private static final Logger log = LoggerFactory.getLogger(JCSDKClient.class);

    final int port;
    final String host;
    SocketChannel channel;
    private byte[] atr;

    public JCSDKClient(String host, int port) {
        this.port = port;
        this.host = host;
    }

    RemoteMessage recv(SocketChannel channel) throws IOException {
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

    RemoteMessage send(SocketChannel channel, RemoteMessage message) throws IOException {
        log.info("Sending " + message.getType());
        switch (message.getType()) {
            case APDU:
                channel.write(JCSDKServer.format((byte) 0x00, message.getPayload()));
                break;
            case ATR:
                channel.write(JCSDKServer.format((byte) 0xF0, message.getPayload()));
                break;
            case POWERDOWN:
                channel.write(JCSDKServer.format((byte) 0xFE, new byte[0]));
                break;
            default:
                log.warn("Unknown message for protocol: " + message.getType());
        }
        return recv(channel);
    }

    public SocketChannel getSocket() throws IOException {
        return AbstractTCPAdapter.connect(host, port);
    }

    @Override
    public void reset() {
        try {
            send(this.channel, new RemoteMessage(RemoteMessage.Type.POWERDOWN));
            this.atr = send(this.channel, new RemoteMessage(RemoteMessage.Type.ATR)).getPayload();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
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
}
