package pro.javacard.jcardsim.adapters;

import com.licel.jcardsim.base.CardInterface;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.jcardsim.core.RemoteMessage;
import pro.javacard.jcardsim.core.RemoteMessage.Type;

import java.io.EOFException;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.concurrent.Callable;

// Minimal generalization to support multiple adapters
public abstract class RemoteTerminalProtocol implements Callable<Boolean> {

    private static final Logger log = LoggerFactory.getLogger(RemoteTerminalProtocol.class);

    static final byte[] DEFAULT_ATR = Hex.decode("3B9F968131FE454F52434C2D4A43332E324750322E3323");

    public void start() throws IOException {
        // No special steps needed for clients.
    }

    public abstract RemoteMessage recv(SocketChannel channel) throws IOException;

    public abstract void send(SocketChannel channel, RemoteMessage message) throws IOException;

    public abstract SocketChannel getSocket() throws IOException;

    final protected CardInterface sim;
    protected byte[] atr;

    protected RemoteTerminalProtocol(CardInterface sim) {
        this(sim, DEFAULT_ATR);
    }

    protected RemoteTerminalProtocol(CardInterface sim, byte[] atr) {
        this.sim = sim;
        this.atr = atr.clone();
    }

    // XXX: not the nicest.
    public void setATR(byte[] atr) {
        this.atr = atr.clone();
    }

    @Override
    public Boolean call() {
        Thread.currentThread().setName(this.getClass().getSimpleName());
        // Start listening or do other setup.
        try {
            start();
        } catch (IOException e) {
            log.error("Could not start: " + e.getMessage(), e);
            throw new RuntimeException("Could not start a remote protocol adapter: " + e.getMessage(), e);
        }
        // Loop many clients / broken sessions
        while (!Thread.currentThread().isInterrupted()) {
            try {
                // New client.
                SocketChannel channel = getSocket();
                // Many messages.
                while (!Thread.currentThread().isInterrupted()) {
                    try {
                        RemoteMessage msg = recv(channel);
                        // Silence noisy VSmartCard ATR request.
                        if (!(this.getClass() == VSmartCard.class && msg.getType() == Type.ATR))
                            log.info("Processing {}", msg.getType());
                        switch (msg.getType()) {
                            case ATR:
                                send(channel, new RemoteMessage(Type.ATR, atr));
                                break;
                            case RESET:
                            case POWERUP:
                            case POWERDOWN:
                                sim.reset();
                                send(channel, new RemoteMessage(Type.POWERDOWN));
                                break;
                            case APDU:
                                byte[] response = sim.transmitCommand(msg.getPayload());
                                send(channel, new RemoteMessage(Type.APDU, response));
                                break;
                            default:
                                log.warn("Unhandled message type: " + msg.getType());
                        }
                    } catch (EOFException e) {
                        log.info("Peer disconnected");
                        break; // new socket
                    } catch (Exception e) {
                        log.error("Error processing client command: " + e.getMessage(), e);
                        break;
                    }
                }
            } catch (SocketException | SocketTimeoutException e) {
                log.error("Could not connect: " + e.getMessage(), e);
                return false;
            } catch (IOException e) {
                log.error("I/O error: " + e.getMessage(), e);
            }
        }
        return true;
    }

    // Connect to remote server
    protected static SocketChannel connect(String host, Integer port) throws IOException {
        InetSocketAddress addr = new InetSocketAddress(host, port);
        SocketChannel sc = SocketChannel.open();
        sc.socket().connect(addr, 3000);
        if (!sc.isConnected()) {
            throw new IOException("Could not connect to " + addr);
        }
        return sc;
    }

    // Start a local server
    protected static ServerSocketChannel start(String host, Integer port) throws IOException {
        InetSocketAddress addr = new InetSocketAddress(host, port);
        ServerSocketChannel server = ServerSocketChannel.open();
        return server.bind(addr);
    }
}
