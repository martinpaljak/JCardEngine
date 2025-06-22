package pro.javacard.jcardsim.core;

import com.licel.jcardsim.base.CardInterface;
import com.licel.jcardsim.base.Helpers;
import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.jcardsim.core.RemoteMessage.Type;

import java.util.List;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.TimeUnit;

// Due to https://github.com/licel/jcardsim/issues/208
// This wraps Simulator into a thread that is automatically started on creation
// As it exposes only "BIBO" interface, setup is done by declarative InstallSpec list
public class ThreadedSimulator implements CardInterface, Runnable {
    private static final Logger log = LoggerFactory.getLogger(ThreadedSimulator.class);

    private final SynchronousQueue<RemoteMessage> queue = new SynchronousQueue<>(true);
    private final List<InstallSpec> applets;
    private Thread thread = new Thread(this); // XXX

    private Simulator sim;

    public ThreadedSimulator(List<InstallSpec> applets) {
        this.applets = applets;
        thread.setDaemon(true);
        thread.start();
    }

    @Override
    public void run() {
        Thread.currentThread().setName("JavaCard");
        // Make the simulator, fixed to this thread.
        try {
            sim = makeSimulator(applets);
        } catch (Exception e) {
            log.error("Could not initialize simulator, exiting.", e);
            return;
        }
        try {
            while (!Thread.currentThread().isInterrupted()) {
                RemoteMessage msg = queue.take();
                log.info("Received message: {}", msg.getType());

                if (msg.type == Type.RESET) {
                    sim.reset();
                    queue.put(new RemoteMessage(Type.RESET));
                } else if (msg.type == Type.APDU) {
                    System.err.println(">> " + Hex.toHexString(msg.payload));
                    byte[] resp = sim.transmitCommand(msg.payload);
                    System.err.println("<< " + Hex.toHexString(resp));
                    queue.put(new RemoteMessage(Type.APDU, resp));
                } else {
                    log.warn("Unknown message type: {}", msg.type);
                }
            }
        } catch (Exception e) {
            log.error("Simulator thread errored", e);
        }
        log.info("Simulator thread exiting");
    }

    private RemoteMessage forward(RemoteMessage msg) {
        // Note: we don't block, to allow for speedy failure in the calling thread
        // even after the simulator thread has died.
        try {
            if (!queue.offer(msg, 100, TimeUnit.MILLISECONDS)) {
                log.error("Timeout when sending command to simulator");
                throw new RuntimeException("Timeout when sending command to simulator");
            }
            // 3 seconds for simulator to respond. Should be sufficient also for 4K RSA generation
            RemoteMessage resp = queue.poll(3, TimeUnit.SECONDS);
            if (resp == null) {
                log.error("Timeout or error when receiving response from simulator");
                throw new RuntimeException("Timeout or error when receiving response from simulator");
            }
            return resp;
        } catch (InterruptedException e) {
            log.error("Interrupted", e);
            throw new RuntimeException("Interrupted", e);
        }
    }

    @Override
    public void reset() {
        RemoteMessage msg = forward(new RemoteMessage(Type.RESET));
        if (msg.getType() != Type.RESET) {
            throw new IllegalStateException("Invalid message type: " + msg.getType());
        }
    }

    @Override
    public byte[] getATR() {
        // XXX: read-only, ignore threads
        return sim.getATR();
    }

    @Override
    public byte[] transmitCommand(byte[] apdu) {
        RemoteMessage msg = new RemoteMessage(Type.APDU, apdu);
        RemoteMessage resp = forward(msg);
        return resp.getPayload();
    }

    @Override
    public String getProtocol() {
        return sim.getProtocol();
    }

    // Called from inside the thread, but exposed for re-usability
    public static Simulator makeSimulator(List<InstallSpec> applets) {
        Simulator sim = new Simulator();
        sim.changeProtocol("T=CL,TYPE_A,T1");
        for (InstallSpec applet : applets) {
            log.info("Installing applet: {} as {} with {}", applet.klass.getSimpleName(), Hex.toHexString(applet.aid), Hex.toHexString(applet.installData));
            byte[] installdata = Helpers.install_parameters(applet.aid, applet.installData);
            AID aid = new AID(applet.aid, (short) 0, (byte) applet.aid.length);
            sim.installApplet(aid, applet.klass, installdata, (short) 0, (byte) installdata.length);
        }
        return sim;
    }
}
