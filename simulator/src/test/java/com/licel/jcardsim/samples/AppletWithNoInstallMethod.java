package com.licel.jcardsim.samples;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public class AppletWithNoInstallMethod extends Applet {

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        // Do nothing
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
}
