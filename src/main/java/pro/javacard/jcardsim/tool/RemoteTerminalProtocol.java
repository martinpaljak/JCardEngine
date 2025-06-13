package pro.javacard.jcardsim.tool;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.io.CardInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

public abstract class RemoteTerminalProtocol implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(RemoteTerminalProtocol.class);

    void start() throws IOException {
        // No special steps needed for clients.
    }

    abstract RemoteMessage recv(SocketChannel channel) throws IOException;

    abstract void send(SocketChannel channel, RemoteMessage message) throws IOException;

    abstract SocketChannel getSocket() throws IOException;

    protected CardInterface sim;

    protected RemoteTerminalProtocol(CardInterface sim) {
        this.sim = sim;
    }

    @Override
    public void run() {
        Thread.currentThread().setName(this.getClass().getSimpleName());
        try {
            start();
        } catch (IOException e) {
            log.error("Could not start: " + e.getMessage(), e);
            throw new RuntimeException("Could not start a remote protocol adapter: " + e.getMessage(), e);
        }
        while (!Thread.currentThread().isInterrupted()) {
            try {
                SocketChannel channel = getSocket();
                RemoteMessage msg = recv(channel);
                switch (msg.type) {
                    case ATR:
                        send(channel, new RemoteMessage(RemoteMessage.Type.ATR, sim.getATR()));
                        break;
                    case RESET:
                    case POWERUP:
                    case POWERDOWN:
                        sim.reset();
                        send(channel, new RemoteMessage(RemoteMessage.Type.RESET, new byte[0]));
                        break;
                    case APDU:
                        byte[] response = sim.transmitCommand(msg.payload);
                        send(channel, new RemoteMessage(RemoteMessage.Type.APDU, response));
                        break;
                }
            } catch (ConnectException e) {
                log.error("Could not connect: " + e.getMessage(), e);
                System.exit(1);
                return;
            } catch (IOException e) {
                log.error("I/O error: " + e.getMessage(), e);
            }
        }
    }

    // Connect to remote server
    static SocketChannel connect(String host, Integer port) throws IOException {
        InetSocketAddress addr = new InetSocketAddress(host, port);
        SocketChannel sc = SocketChannel.open();
        if (!sc.connect(addr)) {
            System.err.println("No connection, false");
        }
        return sc;
    }

    // Start a local server
    static ServerSocketChannel start(String host, Integer port) throws IOException {
        InetSocketAddress addr = new InetSocketAddress(host, port);
        ServerSocketChannel server = ServerSocketChannel.open();
        server.bind(addr);
        return server;
    }
}
