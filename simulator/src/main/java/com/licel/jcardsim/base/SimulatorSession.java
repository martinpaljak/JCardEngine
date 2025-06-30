package com.licel.jcardsim.base;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.engine.core.CardSession;

import java.time.Duration;
import java.util.concurrent.*;

// Session object lifetime guards the held lock for the simulator
public class SimulatorSession implements CardSession {
    private static final Logger log = LoggerFactory.getLogger(SimulatorSession.class);

    // XXX: opportunistic locking requires timed release.
    static ThreadFactory namedThreadFactory = r -> {
        // I like my threads with nice names.
        Thread t = new Thread(r, "IdleWatchdog");
        t.setDaemon(true); // not blocking shutdown
        return t;
    };
    private static final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(namedThreadFactory);
    private final Duration idleTimeout;
    private volatile boolean closed = false;
    private volatile ScheduledFuture<Void> timeoutTask; // associated with this

    // The useful fields
    private final Simulator simulator;
    private final String protocol;
    final Thread owner;
    SimulatorSession(Simulator simulator, String protocol, Duration timeout) {
        log.info("Acquiring lock ...");
        this.simulator = simulator;
        simulator.lock.acquireUninterruptibly();
        idleTimeout = timeout;
        if (!idleTimeout.isZero()) {
            scheduleTimeout();
        }
        // The protocol will be active for the whole session.
        // XXX: verify before locking, so that it would not throw
        simulator.changeProtocol(protocol);
        this.protocol = protocol;
        this.owner = Thread.currentThread();
        log.info("Locked");
    }

    private void scheduleTimeout() {
        timeoutTask = scheduler.schedule(this::timeoutExpired, idleTimeout.toMillis(), TimeUnit.MILLISECONDS);
    }

    private void refreshTimeout() {
        if (timeoutTask != null) {
            timeoutTask.cancel(false);
            scheduleTimeout();
        }
    }

    // Called by scheduler if there has been no APDU traffic for the timeout duration
    private Void timeoutExpired() {
        log.info("Idle timeout, closing session for " + owner.getName());
        close(false);
        return null;
    }

    @Override
    public void close(boolean reset) {
        // Do nothing if already closed
        if (closed) {
            return;
        }
        closed = true;
        if (reset) {
            reset();
        }
        simulator.lock.release();
        log.info("Unlocked");
    }

    @Override
    public void reset() {
        if (closed) {
            throw new IllegalStateException("Session already closed");
        }
        simulator.reset();
    }

    @Override
    public byte[] getATR() {
        if (closed) {
            throw new IllegalStateException("Session already closed");
        }
        return simulator.getATR();
    }

    @Override
    public byte[] transmitCommand(byte[] commandAPDU) {
        if (closed) {
            throw new IllegalStateException("Session already closed");
        }
        refreshTimeout(); // Extend for another period before auto-close
        return simulator._transmitCommand(commandAPDU);
    }

    @Override
    public String getProtocol() {
        if (closed) {
            throw new IllegalStateException("Session already closed");
        }
        return protocol;
    }

    public boolean isClosed() {
        return closed;
    }
}
