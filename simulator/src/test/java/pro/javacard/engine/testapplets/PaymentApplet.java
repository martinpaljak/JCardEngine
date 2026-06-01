// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.testapplets;

import javacard.framework.*;

import org.globalplatform.contactless.GPCLRegistryEntry;
import org.globalplatform.contactless.GPCLSystem;

// Minimal contactless payment-application stand-in for PPSE tests. Its CREL reference, family and
// initial discretionary data are set through INSTALL parameters; INS_UPDATE_DD (CLA=0x80, INS=0xDA)
// writes the application's OWN discretionary data (CDATA = BF0C{61}) into the Contactless Registry,
// registering its Directory Entry at runtime for the PPSE to enumerate.
public final class PaymentApplet extends Applet {

    private static final byte INS_UPDATE_DD = (byte) 0xDA;

    public static void install(byte[] p, short off, byte len) {
        new PaymentApplet().register(p, (short) (off + 1), p[off]);
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_INS] == INS_UPDATE_DD) {
            short lc = apdu.setIncomingAndReceive();
            GPCLSystem.getGPCLRegistryEntry(null).setInfo(buf, ISO7816.OFFSET_CDATA, lc, GPCLRegistryEntry.INFO_DISCRETIONARY_DATA);
            return;
        }
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
}
