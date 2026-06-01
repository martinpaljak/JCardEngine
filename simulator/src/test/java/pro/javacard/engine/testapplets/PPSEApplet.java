// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.testapplets;

import javacard.framework.*;

import org.globalplatform.contactless.CLAppletEvent;
import org.globalplatform.contactless.CRELApplication;
import org.globalplatform.contactless.GPCLRegistryEntry;
import org.globalplatform.contactless.GPCLSystem;

// Multi-mode PPSE (EMVCo PPSE and Application Management for SE v1.0). On SELECT it returns the FCI per
// the current mode (set via SET MODE, default Internal):
//   External (01) - returns the FCI Proprietary Template the device pushed with PUT TEMPLATE.
//   Internal (02) - builds the FCI by enumerating activated financial applications (Table 3-5):
//       6F { 84 '2PAY.SYS.DDF01', A5 { BF0C { 61 ...}+ } }
//   Mutual Exclusivity (03) - Internal, plus on EVENT_ACTIVATED it deactivates the other active payment
//       application(s) so at most one is active (R3.12.2); this needs the CRELApplication wiring.
//
// Each payment application's INFO_DISCRETIONARY_DATA is a BF0C TLV; the merged 61 Directory Entries go
// under one BF0C. With no application to list, the Table 3-4 form (6F { 84 ... }) is returned.
//
// INS_UPDATE_DD (CLA=0x80, INS=0xDA) writes the caller's OWN discretionary data (CDATA = BF0C{61}),
// letting a payment application register its Directory Entry at runtime. Single-byte lengths only; the
// device/antenna interface is not distinguished (commands are accepted regardless of interface).
public final class PPSEApplet extends Applet implements CRELApplication {

    private static final byte MODE_EXTERNAL = (byte) 0x01;
    private static final byte MODE_INTERNAL = (byte) 0x02;
    private static final byte MODE_MUTEX = (byte) 0x03;

    private static final byte INS_PUT_TEMPLATE = (byte) 0xD2;
    private static final byte INS_SET_MODE = (byte) 0xD6;
    private static final byte INS_UPDATE_DD = (byte) 0xDA;

    private static final byte PUT_TEMPLATE_STORE = (byte) 0x01;
    private static final byte PUT_TEMPLATE_DELETE = (byte) 0x05;

    private static final byte FAMILY_FINANCIAL = (byte) 0x20;

    // '2PAY.SYS.DDF01'
    private static final byte[] DF_NAME = {
            (byte) 0x32, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E, (byte) 0x53, (byte) 0x59,
            (byte) 0x53, (byte) 0x2E, (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31};

    private byte mode = MODE_INTERNAL;
    private final byte[] template = new byte[256]; // External-mode FCI Proprietary Template (the A5 TLV)
    private short templateLen;

    private final byte[] scratch = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
    private final Object[] victims = JCSystem.makeTransientObjectArray((short) 8, JCSystem.CLEAR_ON_DESELECT);

    public static void install(byte[] p, short off, byte len) {
        new PPSEApplet().register(p, (short) (off + 1), p[off]);
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) {
            buildFci(apdu);
            return;
        }
        byte[] buf = apdu.getBuffer();
        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_SET_MODE:
                setMode(buf[ISO7816.OFFSET_P1]);
                return;
            case INS_PUT_TEMPLATE:
                putTemplate(apdu, buf);
                return;
            case INS_UPDATE_DD:
                short lc = apdu.setIncomingAndReceive();
                GPCLSystem.getGPCLRegistryEntry(null).setInfo(buf, ISO7816.OFFSET_CDATA, lc, GPCLRegistryEntry.INFO_DISCRETIONARY_DATA);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void setMode(byte p1) {
        if (p1 < MODE_EXTERNAL || p1 > MODE_MUTEX) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        mode = p1;
    }

    private void putTemplate(APDU apdu, byte[] buf) {
        short lc = apdu.setIncomingAndReceive();
        switch (buf[ISO7816.OFFSET_P1]) {
            case PUT_TEMPLATE_STORE:
                Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, template, (short) 0, lc);
                templateLen = lc;
                return;
            case PUT_TEMPLATE_DELETE:
                templateLen = 0;
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    private void buildFci(APDU apdu) {
        byte[] b = apdu.getBuffer();
        short off = 0;
        b[off++] = 0x6F;
        short lenFci = off++;
        b[off++] = (byte) 0x84;
        b[off++] = (byte) DF_NAME.length;
        off = Util.arrayCopyNonAtomic(DF_NAME, (short) 0, b, off, (short) DF_NAME.length);

        if (mode == MODE_EXTERNAL) {
            off = Util.arrayCopyNonAtomic(template, (short) 0, b, off, templateLen);
        } else {
            off = appendDirectory(b, off);
        }
        off = setBerLen(b, lenFci, off);
        apdu.setOutgoingAndSend((short) 0, off);
    }

    // Internal / Mutual Exclusivity: A5 { BF0C { merged 61 entries } } from activated financial apps.
    private short appendDirectory(byte[] b, short off) {
        short afterName = off;
        b[off++] = (byte) 0xA5;
        short lenA5 = off++;
        b[off++] = (byte) 0xBF;
        b[off++] = 0x0C;
        short lenBf = off++;
        short ddStart = off;
        try {
            GPCLRegistryEntry e = GPCLSystem.getNextGPCLRegistryEntry(null, GPCLSystem.AFI_FINANCIAL);
            while (e != null) {
                try {
                    short total = e.getInfo(scratch, (short) 0, GPCLRegistryEntry.INFO_DISCRETIONARY_DATA);
                    off = appendDirEntries(scratch, total, b, off);
                } catch (ISOException getInfoError) {
                    // getInfo throws SW_RECORD_NOT_FOUND when no discretionary data is set: skip the app.
                    if (getInfoError.getReason() != ISO7816.SW_RECORD_NOT_FOUND) {
                        throw getInfoError;
                    }
                }
                e = GPCLSystem.getNextGPCLRegistryEntry(e, GPCLSystem.AFI_FINANCIAL);
            }
        } catch (ISOException enumError) {
            // getNextGPCLRegistryEntry throws only SW_CONDITIONS_NOT_SATISFIED, and only when the caller
            // lacks the registry privilege to enumerate: then return the Table 3-4 form (no template).
            if (enumError.getReason() != ISO7816.SW_CONDITIONS_NOT_SATISFIED) {
                throw enumError;
            }
            off = ddStart;
        }
        if ((short) (off - ddStart) == 0) {
            return afterName; // Table 3-4: no proprietary template
        }
        off = setBerLen(b, lenBf, off);
        off = setBerLen(b, lenA5, off);
        return off;
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

    // Copy the value of a BF0C TLV (the concatenated 61 Directory Entries) from src into dst.
    private static short appendDirEntries(byte[] src, short total, byte[] dst, short dstOff) {
        if (total < 4 || src[0] != (byte) 0xBF || src[1] != 0x0C) {
            return dstOff;
        }
        short p = 2;
        p += (short) ((src[p] & 0x80) == 0 ? 1 : 1 + (src[p] & 0x7F));
        short len = (short) (total - p);
        return len < 0 ? dstOff : Util.arrayCopyNonAtomic(src, p, dst, dstOff, len);
    }

    // GPC v2.3.1 Amd C 3.10: platform fetches the CREL SIO with clientAID=null.
    @Override
    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
        if (parameter == GPCLSystem.GPCL_CREL_APPLICATION) {
            return this;
        }
        return null;
    }

    // R3.12.2: in Mutual Exclusivity mode, when a payment application is activated, deactivate every
    // other currently active payment application (family '20' or no family). Collect first, then
    // deactivate, so deactivating an entry does not disturb the stateless enumeration cursor.
    @Override
    public void notifyCLEvent(GPCLRegistryEntry target, short event) {
        if (mode != MODE_MUTEX || event != CLAppletEvent.EVENT_ACTIVATED) {
            return;
        }
        AID activated = target.getAID();
        short n = 0;
        GPCLRegistryEntry e = GPCLSystem.getNextGPCLRegistryEntry(null, GPCLSystem.AFI_ANY);
        while (e != null && n < (short) victims.length) {
            if (!activated.equals(e.getAID()) && isPaymentApplication(e)) {
                victims[n++] = e;
            }
            e = GPCLSystem.getNextGPCLRegistryEntry(e, GPCLSystem.AFI_ANY);
        }
        for (short i = 0; i < n; i++) {
            ((GPCLRegistryEntry) victims[i]).setCLState(GPCLRegistryEntry.STATE_CL_DEACTIVATED);
            victims[i] = null;
        }
    }

    private boolean isPaymentApplication(GPCLRegistryEntry e) {
        try {
            short end = e.getInfo(scratch, (short) 0, GPCLRegistryEntry.INFO_FAMILY_IDENTIFIER);
            return end > 0 && scratch[(short) (end - 1)] == FAMILY_FINANCIAL; // LSB is the AFI byte
        } catch (ISOException ex) {
            // No Application Family Identifier: treated as a payment application (R3.12.2).
            if (ex.getReason() != ISO7816.SW_RECORD_NOT_FOUND) {
                throw ex;
            }
            return true;
        }
    }
}
