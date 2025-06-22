package com.licel.jcardsim.base;

import javacard.framework.AID;
import javacard.framework.Applet;

// This is the programmer-facing interface. It allows to manage the "secure element" by installing and deleting
// applets, and to open APDU-transports to it.
public interface JavaCardSimulator {
    AID installApplet(AID aid, Class<? extends Applet> appletClass, byte[] parameters);
    void deleteApplet(AID aid);
}
