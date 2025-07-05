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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicReference;

// Minimal generalization to support multiple adapters
public abstract class AbstractTCPAdapter implements Callable<Boolean> {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    static final byte[] DEFAULT_ATR = Hex.decode("3B80800101");

    public void start() throws IOException {
        // No special steps needed for clients.
    }

    public enum AdapterState {
        CONNECTED, DISCONNECTED, RESET, SHUTDOWN
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

    private volatile Thread thread; // Used to interrupt the adapter
    private AdapterState currentState = AdapterState.CONNECTED;

    private final AtomicReference<AdapterState> targetState = new AtomicReference<>(null);
    private final Semaphore semaphore = new Semaphore(1);

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
        // indicate disconnect
        if (!targetState.compareAndSet(null, AdapterState.RESET)) {
            throw new IllegalStateException("Can't trigger reset!");
        }
        // interrupt thread
        thread.interrupt();
        // Wait until processed
        semaphore.acquireUninterruptibly();
    }

    public void connected(boolean flag) {
        targetState.compareAndSet(null, flag ? AdapterState.CONNECTED : AdapterState.DISCONNECTED);
        thread.interrupt();
        // Wait until processed
        semaphore.acquireUninterruptibly();
    }

    @Override
    public Boolean call() {
        this.thread = Thread.currentThread();
        this.thread.setName(this.getClass().getSimpleName());

        // Loop many clients / broken sessions
        while (!Thread.currentThread().isInterrupted()) {
            switch (currentState) {
                case DISCONNECTED:
                    sim.reset();
                    try {
                        Thread.sleep(Long.MAX_VALUE);
                    } catch (InterruptedException e) {
                        log.debug("State changed, checking new state");
                        AdapterState target = targetState.getAndSet(null);
                        this.currentState = (target == null) ? AdapterState.SHUTDOWN : target;
                        semaphore.release();
                    }
                    continue;
                case SHUTDOWN:
                    // Ctrl-C/Orderly shutdown of listening socket
                    log.info("Shutting down. Bye!");
                    return true;
                case RESET:
                    sim.reset();
                    this.currentState = AdapterState.CONNECTED;
                    continue;
                case CONNECTED:
                    try {
                        // Start listening or do other setup.
                        try {
                            start();
                        } catch (IOException e) {
                            log.error("Could not start: " + e.getMessage(), e);
                            throw new RuntimeException("Could not start a remote protocol adapter: " + e.getMessage(), e);
                        }
                        // New client.
                        SocketChannel channel = getSocket();
                        log.info("Serving peer {}", channel.getRemoteAddress());
                        EngineSession session = null;
                        // Many messages while connected
                        while (!Thread.currentThread().isInterrupted() && this.currentState == AdapterState.CONNECTED) {
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
                                        if (Arrays.equals(cmd, Hex.decode("FFCA000000")) && protocol.equals("T=CL")) {
                                            log.info("Intercepting GET UID");
                                            // NOTE: Normally it is the task of a reader driver to fetch the UID from the card
                                            // As we have basic virtual adapters, must intercept this ourselves.
                                            // TODO: parametrize
                                            send(channel, new RemoteMessage(Type.APDU, Hex.decode("040102039000")));
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
                            } catch (EOFException e) {
                                log.info("Peer disconnected");
                                break; // new socket or loop end
                            }
                        }
                    } catch (ClosedByInterruptException e) {
                        if (Thread.interrupted()) {
                            AdapterState target = targetState.getAndSet(null);
                            this.currentState = (target == null) ? AdapterState.SHUTDOWN : target;
                            semaphore.release();
                        }
                    } catch (SocketException | SocketTimeoutException e) {
                        log.error("Connection error: {}", e.getClass().getSimpleName());
                        log.trace("Exception", e);
                        return false;
                    } catch (IOException e) {
                        log.error("I/O error: {}", e.getClass().getSimpleName());
                        log.trace("Exception", e);
                    }
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
