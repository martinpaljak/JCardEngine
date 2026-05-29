// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.testapplets;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

import org.globalplatform.GPSystem;

// Drives GPSystem.getRegistryEntry(null).registerService / deregisterService (GPC v2.3.1 8.1.1) on
// its own registry entry. Reports the outcome SW so tests observe register/deregister behavior.
//
// APDU contract (CLA=0x80, INS=0xEE), CDATA = the 2-byte service name (family, id):
//   P1=0x01 registerService    response = 1 byte 0x01 on success, else 2 bytes = the failure SW
//   P1=0x02 deregisterService  same response convention
public final class GlobalServiceTestApplet extends Applet {

    private static final byte INS = (byte) 0xEE;
    private static final byte P1_REGISTER = (byte) 0x01;
    private static final byte P1_DEREGISTER = (byte) 0x02;

    public static void install(byte[] p, short off, byte len) {
        new GlobalServiceTestApplet().register(p, (short) (off + 1), p[off]);
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_INS] != INS) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        short lc = apdu.setIncomingAndReceive();
        if (lc != 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short name = Util.getShort(buf, ISO7816.OFFSET_CDATA);
        try {
            switch (buf[ISO7816.OFFSET_P1]) {
                case P1_REGISTER:
                    GPSystem.getRegistryEntry(null).registerService(name);
                    break;
                case P1_DEREGISTER:
                    GPSystem.getRegistryEntry(null).deregisterService(name);
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            buf[0] = 0x01;
            apdu.setOutgoingAndSend((short) 0, (short) 1);
        } catch (ISOException e) {
            Util.setShort(buf, (short) 0, e.getReason());
            apdu.setOutgoingAndSend((short) 0, (short) 2);
        }
    }
}
