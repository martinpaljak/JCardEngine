// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.testapplets;

import javacard.framework.*;

import org.globalplatform.contactless.CLAppletEvent;
import org.globalplatform.contactless.CRELApplication;
import org.globalplatform.contactless.GPCLRegistryEntry;
import org.globalplatform.contactless.GPCLSystem;

public final class PPSEApplet extends Applet implements CRELApplication {

    // '2PAY.SYS.DDF01'
    private static final byte[] DF_NAME = {
            (byte) 0x32, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E, (byte) 0x53, (byte) 0x59,
            (byte) 0x53, (byte) 0x2E, (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31};

    private GPCLRegistryEntry current;

    public static void install(byte[] p, short off, byte len) {
        new PPSEApplet().register(p, (short) (off + 1), p[off]);
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) {
            buildFci(apdu);
            return;
        }
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }

    private void buildFci(APDU apdu) {
        byte[] b = apdu.getBuffer();
        short off = 0;
        b[off++] = 0x6F;
        short lenFci = off++;
        b[off++] = (byte) 0x84;
        b[off++] = (byte) DF_NAME.length;
        off = Util.arrayCopyNonAtomic(DF_NAME, (short) 0, b, off, (short) DF_NAME.length);
        if (current != null) {
            b[off] = (byte) 0xA5;
            short lenA5 = (short) (off + 1);
            try {
                short end = current.getInfo(b, (short) (off + 2), GPCLRegistryEntry.INFO_DISCRETIONARY_DATA);
                off = setBerLen(b, lenA5, end);
            } catch (ISOException e) {
                if (e.getReason() != ISO7816.SW_RECORD_NOT_FOUND) {
                    throw e;
                }
            }
        }
        off = setBerLen(b, lenFci, off);
        apdu.setOutgoingAndSend((short) 0, off);
    }

    private static short setBerLen(byte[] b, short lenPos, short end) {
        short content = (short) (end - lenPos - 1);
        if (content < 0x80) {
            b[lenPos] = (byte) content;
            return end;
        }
        Util.arrayCopyNonAtomic(b, (short) (lenPos + 1), b, (short) (lenPos + 2), content);
        b[lenPos] = (byte) 0x81;
        b[(short) (lenPos + 1)] = (byte) content;
        return (short) (end + 1);
    }

    @Override
    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
        return parameter == GPCLSystem.GPCL_CREL_APPLICATION ? this : null;
    }

    @Override
    public void notifyCLEvent(GPCLRegistryEntry target, short event) {
        if (event == CLAppletEvent.EVENT_ACTIVATED) {
            current = target;
        }
    }
}
