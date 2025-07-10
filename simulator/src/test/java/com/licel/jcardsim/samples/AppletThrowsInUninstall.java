package com.licel.jcardsim.samples;

import javacard.framework.*;

public class AppletThrowsInUninstall extends Applet implements AppletEvent {
    public static final boolean jcardengine = false;

    public static void install(byte[] bArray, short bOffset, byte bLength)
            throws ISOException {
        new AppletThrowsInUninstall().register();
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        if (selectingApplet())
            ISOException.throwIt((short) 0x9000);
        ISOException.throwIt((short) (jcardengine ? 0x9002 : 0x9001));
    }

    @Override
    public void uninstall() {
        SystemException.throwIt(SystemException.ILLEGAL_USE);
    }

    @Override
    public void deselect() {
        JCSystem.beginTransaction();
        SystemException.throwIt(SystemException.ILLEGAL_USE);
    }

}
