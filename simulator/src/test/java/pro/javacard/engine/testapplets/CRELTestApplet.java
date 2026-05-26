// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.testapplets;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;

import org.globalplatform.contactless.CLApplet;
import org.globalplatform.contactless.CRELApplication;
import org.globalplatform.contactless.GPCLRegistryEntry;
import org.globalplatform.contactless.GPCLSystem;

// Records CRELApplication / CLApplet callbacks and drives setCLState through GPCLSystem.
// Does no input validation; tests always send well-formed APDUs.
//
// APDU contract (CLA=0x80, INS=0xEE), driven by P1:
//   0x00 dump CREL log   event-hi | event-lo | aid-len | aid-bytes records
//   0x01 clear both logs
//   0x03 self  setCLState(P2)   response = resulting state byte
//   0x04 cross setCLState(P2)   CDATA = target AID, response = resulting state byte
//   0x05 dump self log   event-hi | event-lo records
public final class CRELTestApplet extends Applet implements CRELApplication, CLApplet {

    private final byte[] crelLog = new byte[256];
    private final byte[] selfLog = new byte[64];
    private short crelLen;
    private short selfLen;

    public static void install(byte[] p, short off, byte len) {
        new CRELTestApplet().register(p, (short) (off + 1), p[off]);
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        byte p2 = buf[ISO7816.OFFSET_P2];
        switch (buf[ISO7816.OFFSET_P1]) {
            case 0x00 -> sendAndReset(apdu, buf, crelLog, crelLen);
            case 0x01 -> { crelLen = 0; selfLen = 0; }
            case 0x03 -> setCLStateReply(apdu, buf, p2, GPCLSystem.getGPCLRegistryEntry(null));
            case 0x04 -> {
                short lc = apdu.setIncomingAndReceive();
                var target = GPCLSystem.getGPCLRegistryEntry(JCSystem.lookupAID(buf, ISO7816.OFFSET_CDATA, (byte) lc));
                setCLStateReply(apdu, buf, p2, target);
            }
            case 0x05 -> sendAndReset(apdu, buf, selfLog, selfLen);
        }
    }

    private static void sendAndReset(APDU apdu, byte[] buf, byte[] log, short len) {
        Util.arrayCopyNonAtomic(log, (short) 0, buf, (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    private static void setCLStateReply(APDU apdu, byte[] buf, byte state, GPCLRegistryEntry target) {
        buf[0] = target.setCLState(state);
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    // GPC v2.3.1 Amd C 3.10: platform fetches CREL/CLApplet SIOs with clientAID=null.
    @Override
    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
        if (clientAID != null) {
            return null;
        }
        if (parameter == GPCLSystem.GPCL_CREL_APPLICATION || parameter == GPCLSystem.GPCL_CL_APPLICATION) {
            return this;
        }
        return null;
    }

    @Override
    public void notifyCLEvent(GPCLRegistryEntry source, short event) {
        crelLog[crelLen++] = (byte) (event >> 8);
        crelLog[crelLen++] = (byte) event;
        byte aidLen = source.getAID().getBytes(crelLog, (short) (crelLen + 1));
        crelLog[crelLen] = aidLen;
        crelLen += (short) (1 + aidLen);
        // prev-null flag: platform dispatch must have getPreviousContextAID()==null.
        crelLog[crelLen++] = (byte) (JCSystem.getPreviousContextAID() == null ? 0x01 : 0x00);
    }

    @Override
    public void notifyCLEvent(short event) {
        selfLog[selfLen++] = (byte) (event >> 8);
        selfLog[selfLen++] = (byte) event;
        selfLog[selfLen++] = (byte) (JCSystem.getPreviousContextAID() == null ? 0x01 : 0x00);
    }
}
