// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.testapplets;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;

import org.globalplatform.GPRegistryEntry;
import org.globalplatform.contactless.CLAppletEvent;
import org.globalplatform.contactless.CRELApplication;
import org.globalplatform.contactless.CRSApplication;
import org.globalplatform.contactless.GPCLRegistryEntry;
import org.globalplatform.contactless.GPCLSystem;

// Effective-CRS stand-in for GPC v2.3.1 Amd C 3.10.3 implicit subscription tests. Records every
// notifyCLEvent and exposes a dump APDU.
//
// APDU contract (CLA=0x80, INS=0xEE), driven by P1:
//   0x00 dump CREL log   event-hi | event-lo | aid-len | aid-bytes records
//   0x01 clear log
//   0x02 processCLRequest toggle: P2=0 reject, P2=1 approve (default: approve)
//   0x03 cross setCLState(P2) on target named in CDATA; response = resulting state byte
public final class CRSTestApplet extends Applet implements CRSApplication {

    private final byte[] crelLog = new byte[256];
    private short crelLen;
    private boolean approveRequests = true;

    public static void install(byte[] p, short off, byte len) {
        // CRS role requires ContactlessActivation + GlobalRegistry.
        short privOff = (short) (off + 1 + p[off]);
        byte privLen = p[privOff];
        if (!granted(p, (short) (privOff + 1), privLen, GPCLRegistryEntry.PRIVILEGE_CONTACTLESS_ACTIVATION)
                || !granted(p, (short) (privOff + 1), privLen, GPRegistryEntry.PRIVILEGE_GLOBAL_REGISTRY)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        new CRSTestApplet().register(p, (short) (off + 1), p[off]);
    }

    // GP privilege bit n -> byte n>>3, mask 0x80 >> (n & 7).
    private static boolean granted(byte[] b, short privOff, byte privLen, byte priv) {
        short idx = (short) (priv >> 3);
        if (idx >= privLen) {
            return false;
        }
        return (b[(short) (privOff + idx)] & (0x80 >> (priv & 0x07))) != 0;
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        byte p2 = buf[ISO7816.OFFSET_P2];
        switch (buf[ISO7816.OFFSET_P1]) {
            case 0x00: {
                Util.arrayCopyNonAtomic(crelLog, (short) 0, buf, (short) 0, crelLen);
                apdu.setOutgoingAndSend((short) 0, crelLen);
                break;
            }
            case 0x01:
                crelLen = 0;
                break;
            case 0x02:
                approveRequests = p2 != 0;
                break;
            case 0x03: {
                short lc = apdu.setIncomingAndReceive();
                GPCLRegistryEntry target = GPCLSystem.getGPCLRegistryEntry(
                        JCSystem.lookupAID(buf, ISO7816.OFFSET_CDATA, (byte) lc));
                buf[0] = target.setCLState(p2);
                apdu.setOutgoingAndSend((short) 0, (short) 1);
                break;
            }
        }
    }

    // GPC v2.3.1 Amd C 3.10: platform fetches CRS/CREL SIOs with clientAID=null.
    @Override
    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
        if (clientAID != null) {
            return null;
        }
        if (parameter == GPCLSystem.GPCL_CRS_APPLICATION || parameter == GPCLSystem.GPCL_CREL_APPLICATION) {
            return this;
        }
        return null;
    }

    // Record every event; prev-null flag probes the platform-context contract.
    @Override
    public void notifyCLEvent(GPCLRegistryEntry source, short event) {
        crelLog[crelLen++] = (byte) (event >> 8);
        crelLog[crelLen++] = (byte) event;
        byte aidLen = source.getAID().getBytes(crelLog, (short) (crelLen + 1));
        crelLog[crelLen] = aidLen;
        crelLen += (short) (1 + aidLen);
        crelLog[crelLen++] = (byte) (JCSystem.getPreviousContextAID() == null ? 0x01 : 0x00);
    }

    // processCLRequest: setCLState delegates here when an unprivileged applet self-activates
    // (GPC v2.3.1 Amd C 3.11.4.2.2). Toggle picks approve/reject; default approve.
    @Override
    public boolean processCLRequest(GPRegistryEntry requester, GPCLRegistryEntry target, short event) {
        if (!approveRequests || event != CLAppletEvent.EVENT_ACTIVATED) {
            return false;
        }
        target.setCLState(GPCLRegistryEntry.STATE_CL_ACTIVATED);
        return true;
    }
}
