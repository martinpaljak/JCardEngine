package pro.javacard.jcardsim.tool;

import com.licel.jcardsim.base.CardInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

public abstract class RemoteTerminalProtocol implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(RemoteTerminalProtocol.class);

    public void start() throws IOException {
        // No special steps needed for clients.
    }

    public abstract RemoteMessage recv(SocketChannel channel) throws IOException;

    public abstract void send(SocketChannel channel, RemoteMessage message) throws IOException;

    public abstract SocketChannel getSocket() throws IOException;

    protected CardInterface sim;

    protected RemoteTerminalProtocol(CardInterface sim) {
        this.sim = sim;
    }

    @Override
    public void run() {
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
                        if (!(this.getClass() == VSmartCard.class && msg.type == RemoteMessage.Type.ATR))
                            log.info("Processing {}", msg.getType());
                        switch (msg.type) {
                            case ATR:
                                send(channel, new RemoteMessage(RemoteMessage.Type.ATR, JCSDKServer.ATR_SDK));
                                break;
                            case RESET:
                            case POWERUP:
                            case POWERDOWN:
                                sim.reset();
                                send(channel, new RemoteMessage(RemoteMessage.Type.POWERDOWN));
                                break;
                            case APDU:
                                byte[] response = sim.transmitCommand(msg.payload);
                                send(channel, new RemoteMessage(RemoteMessage.Type.APDU, response));
                                break;
                        }
                    } catch (EOFException e) {
                        log.info("Peer disconnected");
                        break; // new socket
                    } catch (Exception e) {
                        log.error("Error processing client command: " + e.getMessage(), e);
                        break;
                    }
                }
            } catch (ConnectException e) {
                log.error("Could not connect: " + e.getMessage(), e);
                System.exit(1); // FIXME: no exit here.
                return;
            } catch (IOException e) {
                log.error("I/O error: " + e.getMessage(), e);
            }
        }
    }

    // Connect to remote server
    protected static SocketChannel connect(String host, Integer port) throws IOException {
        InetSocketAddress addr = new InetSocketAddress(host, port);
        SocketChannel sc = SocketChannel.open();
        sc.configureBlocking(true);
        if (!sc.connect(addr)) {
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
