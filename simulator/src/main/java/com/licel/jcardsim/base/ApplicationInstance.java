package com.licel.jcardsim.base;

import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Applet;

/**
 * Represents an Applet instance
 */
public class ApplicationInstance {
    // TODO: track privileges of install
    private final AID aid;
    private final Object instance;
    private final boolean exposed;

    public ApplicationInstance(AID aid, Object instance, boolean exposed) {
        this.aid = aid;
        this.instance = instance;
        this.exposed = exposed;
    }

    public Applet getApplet() {
        if (exposed) {
            return (Applet) instance;
        }
        try {
            return ReflectiveClassProxy.proxy(instance, Applet.class);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public AID getAID() {
        return aid;
    }

    @Override
    public String toString() {
        return String.format("ApplicationInstance (%s)", AIDUtil.toString(aid));
    }
}
