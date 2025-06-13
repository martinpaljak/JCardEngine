package pro.javacard.jcardsim.tool;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.io.CardInterface;
import javacard.framework.AID;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.TimeUnit;

// Due to threadlocals
public class ThreadedSimulator implements CardInterface, Runnable {

    private static final Logger log = LoggerFactory.getLogger(ThreadedSimulator.class);

    final SynchronousQueue<RemoteMessage> queue = new SynchronousQueue<>(true);
    final List<InstallSpec> applets;
    Thread thread = new Thread(this); // XXX

    Simulator sim;

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
            log.error("Could not initialize simulator");
            return;
        }
        try {
            while (!Thread.currentThread().isInterrupted()) {
                RemoteMessage msg = queue.take();
                log.info("Received message: {}", msg.getType());

                if (msg.type == RemoteMessage.Type.RESET) {
                    sim.reset();
                    queue.put(new RemoteMessage(RemoteMessage.Type.RESET));
                } else if (msg.type == RemoteMessage.Type.APDU) {
                    System.err.println(">> " + Hex.toHexString(msg.payload));
                    byte[] resp = sim.transmitCommand(msg.payload);
                    System.err.println("<< " + Hex.toHexString(resp));
                    queue.put(new RemoteMessage(RemoteMessage.Type.APDU, resp));
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            log.error("Thread done", e);
        }
    }

    @Override
    public void reset() {
        try {
            if (!queue.offer(new RemoteMessage(RemoteMessage.Type.RESET), 300, TimeUnit.MILLISECONDS)) {
                log.error("Timeout when sending command to simulator");
                throw new RuntimeException("Timeout when sending command to simulator");
            }
            RemoteMessage resp = queue.poll(3, TimeUnit.SECONDS);
            if (resp == null || resp.type != RemoteMessage.Type.RESET) {
                log.error("Timeout or error when receiving response from simulator");
                throw new RuntimeException("Timeout or error when receiving response from simulator");
            }
        } catch (InterruptedException e) {
            log.error("Interrupted", e);
            throw new RuntimeException("Interrupted", e);
        }
    }

    @Override
    public byte[] getATR() {
        // XXX: read-only, ignore threads
        return sim.getATR();
    }

    @Override
    public byte[] transmitCommand(byte[] apdu) {
        log.info("Sending APDU to simulator thread: {}", Hex.toHexString(apdu));
        RemoteMessage msg = new RemoteMessage(RemoteMessage.Type.APDU, apdu);
        try {
            if (!queue.offer(msg, 300, TimeUnit.MILLISECONDS)) {
                log.error("Timeout when sending command to simulator");
                throw new RuntimeException("Timeout when sending command to simulator");
            }
            RemoteMessage resp = queue.poll(3, TimeUnit.SECONDS);
            if (resp == null || resp.type != RemoteMessage.Type.APDU) {
                log.error("Timeout or error when receiving response from simulator");
                throw new RuntimeException("Timeout or error when receiving response from simulator");
            }
            return resp.payload;
        } catch (InterruptedException e) {
            log.error("Interrupted", e);
            throw new RuntimeException("Interrupted", e);
        }
    }

    static byte[] install_data(byte[] aid, byte[] data) {
        if (data == null)
            data = new byte[0];
        byte[] fullData = new byte[1 + aid.length + 1 + 1 + 1 + data.length];
        int offset = 0;
        fullData[offset++] = (byte) aid.length;
        System.arraycopy(aid, 0, fullData, offset, aid.length);
        offset += aid.length;
        // NOTE: dummy privileges
        fullData[offset++] = 0x01;
        fullData[offset++] = 0x00;
        fullData[offset++] = (byte) data.length;
        System.arraycopy(data, 0, fullData, offset, data.length);
        return fullData;
    }

    // Called from a thread
    static Simulator makeSimulator(List<InstallSpec> applets) {
        Simulator sim = new Simulator();
        sim.changeProtocol("T=CL,TYPE_A,T1");
        for (InstallSpec applet : applets) {
            log.info("Installing applet: {} as {} with {}", applet.klass.getSimpleName(), Hex.toHexString(applet.aid), Hex.toHexString(applet.installData));
            byte[] installdata = install_data(applet.aid, applet.installData);
            AID aid = new AID(applet.aid, (short) 0, (byte) applet.aid.length);
            sim.installApplet(aid, applet.klass, installdata, (short) 0, (byte) installdata.length);
        }
        return sim;
    }
}
