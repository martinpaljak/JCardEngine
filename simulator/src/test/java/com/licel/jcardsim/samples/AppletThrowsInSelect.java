// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.samples;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.SystemException;

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
