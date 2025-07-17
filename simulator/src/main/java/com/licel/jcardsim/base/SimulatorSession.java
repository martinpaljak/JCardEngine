/*
 * Copyright 2025 Martin Paljak <martin@martinpaljak.net>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.licel.jcardsim.base;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.engine.EngineSession;

import java.time.Duration;
import java.util.concurrent.*;

// Session object lifetime guards the held lock for the simulator
public class SimulatorSession implements EngineSession {
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
        log.trace("Acquiring lock ...");
        this.simulator = simulator;
        simulator.lock.acquireUninterruptibly();
        idleTimeout = timeout;
        if (!idleTimeout.isZero()) {
            scheduleTimeout();
        }
        this.protocol = protocol;
        this.owner = Thread.currentThread();
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
            simulator.reset();
        }
        simulator.lock.release();
        log.trace("Unlocked");
    }

    @Override
    public byte[] transmitCommand(byte[] commandAPDU) {
        if (closed) {
            throw new IllegalStateException("Session already closed");
        }
        refreshTimeout(); // Extend for another period before auto-close
        // XXX: single parse for string
        return simulator._transmitCommand(APDUHelper.getProtocolByte(protocol), commandAPDU);
    }

    @Override
    public String getProtocol() {
        if (closed) {
            throw new IllegalStateException("Session already closed");
        }
        return protocol;
    }

    @Override
    public boolean isClosed() {
        return closed;
    }
}
