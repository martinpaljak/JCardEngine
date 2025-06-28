package com.licel.jcardsim.base;

// Session object lifetime guards the held lock for the simulator
public class SimulatorSession implements CardSession {
    private final Simulator simulator;
    private volatile boolean locked;
    private final String protocol;

    SimulatorSession(Simulator simulator, String protocol) {
        this.simulator = simulator;
        simulator.lock.lock();
        locked = true;
        // The protocol will be active for the whole session.
        simulator.changeProtocol(protocol);
        this.protocol = protocol;
    }

    @Override
    public void close(boolean reset) {
        if (!locked)
            return;
        if (reset)
            reset();
        simulator.lock.unlock();
        locked = false;
    }

    @Override
    public void reset() {
        if (!locked) {
            throw new IllegalStateException("Session already closed");
        }
        simulator.reset();
    }

    @Override
    public byte[] getATR() {
        if (!locked) {
            throw new IllegalStateException("Session already closed");
        }
        return simulator.getATR();
    }

    @Override
    public byte[] transmitCommand(byte[] commandAPDU) {
        if (!locked) {
            throw new IllegalStateException("Session already closed");
        }
        return simulator._transmitCommand(commandAPDU);
    }

    @Override
    public String getProtocol() {
        if (!locked) {
            throw new IllegalStateException("Incorrect usage outside of connect()");
        }
        return protocol;
    }
}
