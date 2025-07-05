package pro.javacard.engine.core;

import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import javacard.framework.Applet;

import java.time.Duration;

// This is the external, programmer-facing interface. It allows to manage the "secure element" by installing and deleting
// applets, and to open APDU-transports to it.
public interface JavaCardEngine {
    AID installApplet(AID aid, Class<? extends Applet> appletClass, byte[] parameters);

    default AID installApplet(AID aid, Class<? extends Applet> appletClass) {
        return installApplet(aid, appletClass, new byte[0]);
    }

    AID installExposedApplet(AID aid, Class<? extends Applet> appletClass, byte[] parameters);

    default AID installExposedApplet(AID aid, Class<? extends Applet> appletClass) {
        return installExposedApplet(aid, appletClass, new byte[0]);
    }

    void deleteApplet(AID aid);

    Applet getApplet(AID aid);

    void reset();

    default EngineSession connect() {
        return connectFor(Duration.ZERO, "*");
    }

    default EngineSession connect(String protocol) {
        return connectFor(Duration.ZERO, protocol);
    }

    EngineSession connectFor(Duration duration, String protocol);

    JavaCardEngine exposed(boolean flag);

    JavaCardEngine withClassLoader(ClassLoader parent);

    static JavaCardEngine create() {
        return new Simulator();
    }
}
