// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.samples;

import javacard.framework.*;

public class DummyApplet extends Applet implements AppletEvent {
    public static boolean exceptionInSelect = false;
    public static boolean exceptionInInstall = false;
    public static boolean exceptionInDeselect = false;
    public static boolean exceptionInUninstall = false;
    public static boolean exceptionIllegalUse1 = false;
    public static boolean exceptionIllegalUse2 = false;

    @SuppressWarnings("unused")
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        exceptionInSelect = false;
        exceptionInInstall = false;
        exceptionInDeselect = false;
        exceptionInUninstall = false;
        exceptionIllegalUse1 = false;
        exceptionIllegalUse2 = false;

        try {
            APDU.getCurrentAPDU();
        } catch (SecurityException se) {
            exceptionInInstall = true;
        }

        new DummyApplet().register();
    }

    @Override
    public boolean select() {
        try {
            APDU.getCurrentAPDU();
        } catch (SecurityException se) {
            exceptionInSelect = true;
        }
        return true;
    }

    @Override
    public void process(APDU a) throws ISOException {
        APDU apdu = APDU.getCurrentAPDU();
        try {
            apdu.getIncomingLength();
            exceptionIllegalUse1 = false;
        } catch (APDUException e) {
            exceptionIllegalUse1 = e.getReason() == APDUException.ILLEGAL_USE;
        }
        try {
            apdu.getOffsetCdata();
            exceptionIllegalUse2 = false;
        } catch (APDUException e) {
            exceptionIllegalUse2 = e.getReason() == APDUException.ILLEGAL_USE;
        }
        apdu.setIncomingAndReceive();
        apdu.getIncomingLength();
        apdu.getOffsetCdata();
    }

    @Override
    public void deselect() {
        try {
            APDU.getCurrentAPDU();
        } catch (SecurityException se) {
            exceptionInDeselect = true;
        }
    }

    public void uninstall() {
        try {
            APDU.getCurrentAPDU();
        } catch (SecurityException se) {
            exceptionInUninstall = true;
        }
    }
}
