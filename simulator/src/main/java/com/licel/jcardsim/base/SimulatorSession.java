// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

import apdu4j.core.BIBO;
import javacard.framework.APDU;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.*;

// Session object lifetime guards the held lock for the simulator
// XXX: opportunistic locking requires timed release.
public class SimulatorSession implements BIBO {
    private static final Logger log = LoggerFactory.getLogger(SimulatorSession.class);

    // I like my threads with nice names.
    static ThreadFactory namedThreadFactory = r -> {
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
    private final byte protocol_byte;
    private final boolean resetOnClose;
    final Thread owner;

    SimulatorSession(Simulator simulator, String protocol, Duration timeout, boolean resetOnClose) {
        this.simulator = simulator;
        this.owner = Thread.currentThread();
        this.protocol = protocol;
        this.resetOnClose = resetOnClose;
        // Before the lock, so an unusable protocol leaves nothing to release
        protocol_byte = getProtocolByte(protocol);
        log.trace("Acquiring lock ...");
        simulator.lock.acquireUninterruptibly();
        idleTimeout = timeout;
        if (!idleTimeout.isZero()) {
            scheduleTimeout();
        }
        log.trace("Locked");
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
        close();
        return null;
    }

    @Override
    public void close() {
        // Do nothing if already closed
        if (closed) {
            return;
        }
        closed = true;
        if (resetOnClose) {
            simulator.reset();
        }
        simulator.lock.release();
        log.trace("Unlocked");
    }

    @Override
    public byte[] transceive(byte[] commandAPDU) {
        Objects.requireNonNull(commandAPDU, "commandAPDU");
        if (closed) {
            throw new IllegalStateException("Session already closed");
        }
        refreshTimeout(); // Extend for another period before auto-close
        return simulator._transceive(protocol_byte, commandAPDU);
    }

    // Converts the protocol string to the internal protocol byte JavaCard expects
    static byte getProtocolByte(String protocol) {
        Objects.requireNonNull(protocol, "protocol");
        String p = protocol.toUpperCase(Locale.ENGLISH).replace(" ", "");
        byte protocolByte;

        if (p.equals("T=0") || p.equals("*")) {
            protocolByte = APDU.PROTOCOL_T0;
        } else if (p.equals("T=1")) {
            protocolByte = APDU.PROTOCOL_T1;
        } else if (p.equals("T=CL,TYPE_A,T1") || p.equals("T=CL")) {
            protocolByte = APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A;
            protocolByte |= APDU.PROTOCOL_T1;
        } else if (p.equals("T=CL,TYPE_B,T1")) {
            protocolByte = APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B;
            protocolByte |= APDU.PROTOCOL_T1;
        } else {
            throw new IllegalArgumentException("Unknown protocol: " + protocol);
        }
        return protocolByte;
    }
}
