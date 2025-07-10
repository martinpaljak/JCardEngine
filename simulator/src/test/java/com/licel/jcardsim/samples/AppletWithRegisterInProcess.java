package com.licel.jcardsim.samples;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;

public class AppletWithRegisterInProcess extends Applet {

    public static void install(byte[] bArray, short bOffset, byte bLength)
            throws ISOException {
        new AppletWithRegisterInProcess().register();
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        register();
    }
}
