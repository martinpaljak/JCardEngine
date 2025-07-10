package com.licel.jcardsim.samples;

import javacard.framework.*;

public class AppletThrowsInSelect extends Applet {

    public static void install(byte[] bArray, short bOffset, byte bLength)
            throws ISOException {
        new AppletThrowsInSelect().register();
    }

    @Override
    public boolean select() {
        SystemException.throwIt(SystemException.ILLEGAL_USE);
        return true;
    }

    @Override
    public void process(APDU apdu) throws ISOException {
    }
}
