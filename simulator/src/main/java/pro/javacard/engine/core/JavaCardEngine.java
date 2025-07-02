package pro.javacard.engine.core;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.base.SimulatorSession;
import javacard.framework.AID;
import javacard.framework.Applet;

import java.time.Duration;

// This is the external, programmer-facing interface. It allows to manage the "secure element" by installing and deleting
// applets, and to open APDU-transports to it.
public interface JavaCardEngine {
    AID installApplet(AID aid, Class<? extends Applet> appletClass, byte[] parameters);

    AID installExposedApplet(AID aid, Class<? extends Applet> appletClass, byte[] parameters);

    void deleteApplet(AID aid);

    Applet getApplet(AID aid);

    void reset();

    EngineSession connect(String protocol);

    EngineSession connectFor(Duration duration, String protocol);

    static JavaCardEngine create() {
        return new Simulator();
    }
}
