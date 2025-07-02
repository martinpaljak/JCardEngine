package pro.javacard.engine.adapters;

import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.engine.adapters.RemoteMessage.Type;
import pro.javacard.engine.core.EngineSession;
import pro.javacard.engine.core.JavaCardEngine;

import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.Callable;

// Minimal generalization to support multiple adapters
public abstract class AbstractTCPAdapter implements Callable<Boolean> {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    public static class OSDetector {

        public enum OS {
            WINDOWS, MAC, LINUX, OTHER
        }

        public static final OS CURRENT_OS = detectOS();

        private static OS detectOS() {
            String osName = System.getProperty("os.name").toLowerCase();

            if (osName.contains("win")) {
                return OS.WINDOWS;
            } else if (osName.contains("mac")) {
                return OS.MAC;
            } else if (osName.contains("nux")) {
                return OS.LINUX;
            } else {
                return OS.OTHER;
            }
        }
    }

    static final byte[] DEFAULT_ATR = Hex.decode("3B9F968131FE454F52434C2D4A43332E324750322E3323");

    public void start() throws IOException {
        // No special steps needed for clients.
    }

    public abstract RemoteMessage recv(SocketChannel channel) throws IOException;

    public abstract void send(SocketChannel channel, RemoteMessage message) throws IOException;

    public abstract SocketChannel getSocket() throws IOException;

    final protected JavaCardEngine sim;
    protected byte[] atr = DEFAULT_ATR;
    protected String protocol = "*";
    private Duration idleTimeout = Duration.ZERO;
    protected String host;
    protected int port;
    private volatile Thread thread;
    private volatile boolean tap;

    protected AbstractTCPAdapter(String host, int port, JavaCardEngine sim) {
        this.sim = sim;
        this.host = host;
        this.port = port;
    }

    protected AbstractTCPAdapter(JavaCardEngine sim) {
        this.sim = sim;
    }

    public AbstractTCPAdapter withATR(byte[] atr) {
        this.atr = atr.clone();
        return this;
    }

    public AbstractTCPAdapter withPort(int port) {
        this.port = port;
        return this;
    }

    public AbstractTCPAdapter withHost(String host) {
        this.host = host;
        return this;
    }

    public AbstractTCPAdapter withProtocol(String protocol) {
        this.protocol = protocol;
        return this;
    }

    public AbstractTCPAdapter withTimeout(Duration duration) {
        this.idleTimeout = duration;
        return this;
    }

    // Safe to call from any thread.
    public void tap() {
        log.info("Triggering tap");
        this.tap = true;
        thread.interrupt();
    }

    @Override
    public Boolean call() {
        Thread.currentThread().setName(this.getClass().getSimpleName());
        this.thread = Thread.currentThread();
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
                log.info("Serving peer {}", channel.getRemoteAddress());
                EngineSession session = null;
                // Many messages.
                while (!Thread.currentThread().isInterrupted()) {
                    //log.trace("Message tap: {}", tap);
                    try {
                        RemoteMessage msg = recv(channel);
                        // Silence noisy VSmartCard ATR request.
                        if (!(this.getClass() == VSmartCardClient.class && msg.getType() == Type.ATR))
                            log.trace("Processing {}", msg.getType());
                        switch (msg.getType()) {
                            case ATR:
                                // NOTE: this is spammed by vsmartcard on every second.
                                // There's no way to indicate "there's no card, thus no ATR"
                                send(channel, new RemoteMessage(Type.ATR, atr));
                                break;
                            case RESET:
                                // NOTE: on Windows and macOS a connection "Starts" with a reset, so we open a connection on demand
                                if (session == null || session.isClosed()) {
                                    session = sim.connectFor(idleTimeout, protocol);
                                }
                                if (session != null) {
                                    session.reset();
                                }
                                send(channel, new RemoteMessage(Type.RESET));
                                break;
                            case POWERUP:
                                // Happens on Linux with vsmartcard
                                if (session != null) {
                                    log.warn("Session is not null");
                                }
                                session = sim.connectFor(idleTimeout, protocol);
                                send(channel, new RemoteMessage(Type.POWERUP));
                                break;
                            case POWERDOWN:
                                // Happens on mac/linux
                                if (session != null) {
                                    session.close(true); // FIXME: no reset ?
                                }
                                session = null;
                                send(channel, new RemoteMessage(Type.POWERDOWN));
                                break;
                            case APDU:
                                if (session == null) {
                                    log.error("No session opened before APDU-s!");
                                    session = sim.connectFor(idleTimeout, protocol);
                                }
                                byte[] cmd = msg.getPayload();
                                if (Arrays.equals(cmd, Hex.decode("ffca000000")) && protocol.equals("T=CL")) {
                                    log.info("Intercepting GET UID");
                                    // NOTE: Normally it is the task of a reader to fetch the UID from the card
                                    // TODO: parametrize
                                    send(channel, new RemoteMessage(Type.APDU, Hex.decode("88F24AB73D915E9000")));
                                    break;
                                }
                                log.info(">> {}", Hex.toHexString(cmd));
                                byte[] response = session.transmitCommand(cmd);
                                log.info("<< {}", Hex.toHexString(response));
                                send(channel, new RemoteMessage(Type.APDU, response));
                                break;
                            default:
                                log.warn("Unhandled message type: " + msg.getType());
                        }
                    } catch (EOFException | ClosedByInterruptException e) {
                        log.info("Peer disconnected");
                        if (Thread.interrupted()) {
                            if (tap) {
                                log.info("Processing tap");
                                tap = false;
                                sim.reset();
                            } else {
                                // Interrupted, but no tap -> done
                                log.info("Interrupted, closing");
                                return false;
                            }
                        }
                        break; // new socket or loop end
                    } catch (Exception e) {
                        log.error("Error processing client command: " + e.getMessage(), e);
                        break;
                    }
                }
            } catch (ClosedByInterruptException e) {
                if (Thread.interrupted()) {
                    if (tap) {
                        log.info("Processing tap");
                        tap = false;
                        sim.reset();
                        // Re-open listening socket
                        try {
                            start();
                        } catch (IOException e2) {
                            log.error("Could not restart: " + e2.getMessage(), e2);
                            throw new RuntimeException("Could not restart a remote protocol adapter: " + e2.getMessage(), e2);
                        }
                        // Continue servig clients
                        continue;
                    } else {
                        log.info("Shutting down. Bye!");
                        // Ctrl-C/Orderly shutdown of listening socket
                        return true;
                    }
                }
            } catch (SocketException | SocketTimeoutException e) {
                log.error("Connection error: {}", e.getClass().getSimpleName());
                log.trace("Exception", e);
                return false;
            } catch (IOException e) {
                log.error("I/O error: {}", e.getClass().getSimpleName());
                log.trace("Exception", e);
            }
            log.trace("Adapter loop done");
        }
        log.info("Adapter thread done");
        return true;
    }

    // Connect to remote server
    public static SocketChannel connect(String host, Integer port) throws IOException {
        InetSocketAddress addr = new InetSocketAddress(host, port);
        SocketChannel sc = SocketChannel.open();
        sc.socket().connect(addr, 3000); // TODO: tunable
        if (!sc.isConnected()) {
            throw new IOException("Could not connect to " + addr);
        }
        return sc;
    }

    // Start a local server
    public static ServerSocketChannel start(String host, Integer port) throws IOException {
        InetSocketAddress addr = new InetSocketAddress(host, port);
        ServerSocketChannel server = ServerSocketChannel.open();
        return server.bind(addr);
    }

    @Override
    public String toString() {
        return String.format("%s{host=%s port=%d atr=%s protocol=%s}", this.getClass().getSimpleName(), host, port, Hex.toHexString(atr), protocol);
    }
}
