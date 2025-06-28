package com.licel.jcardsim.base;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Session object lifetime guards the held lock for the simulator
public class SimulatorSession implements CardSession {
    private static final Logger log = LoggerFactory.getLogger(SimulatorSession.class);
    private final Simulator simulator;
    private final String protocol;

    SimulatorSession(Simulator simulator, String protocol) {
        this.simulator = simulator;
        simulator.lock.lock();
        // The protocol will be active for the whole session.
        // XXX: verify before locking, so that it would not throw
        simulator.changeProtocol(protocol);
        this.protocol = protocol;
        log.info("Locked");
    }

    @Override
    public void close(boolean reset) {
        if (!simulator.lock.isHeldByCurrentThread()) {
            log.error("Simulator.session() called from incorrect thread");
            return;
        }
        if (reset) {
            reset();
        }
        simulator.lock.unlock();
        log.info("Unlocked");
    }

    @Override
    public void reset() {
        if (!simulator.lock.isHeldByCurrentThread()) {
            throw new IllegalStateException("Session already closed");
        }
        simulator.reset();
    }

    @Override
    public byte[] getATR() {
        if (!simulator.lock.isHeldByCurrentThread()) {
            throw new IllegalStateException("Session already closed");
        }
        return simulator.getATR();
    }

    @Override
    public byte[] transmitCommand(byte[] commandAPDU) {
        if (!simulator.lock.isHeldByCurrentThread()) {
            throw new IllegalStateException("Session already closed");
        }
        return simulator._transmitCommand(commandAPDU);
    }

    @Override
    public String getProtocol() {
        if (!simulator.lock.isHeldByCurrentThread()) {
            throw new IllegalStateException("Session already closed");
        }
        return protocol;
    }
}
