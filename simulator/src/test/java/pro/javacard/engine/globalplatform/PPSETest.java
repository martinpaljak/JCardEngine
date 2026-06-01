// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.engine.testapplets.PPSEApplet;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPSession;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.Tag;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static pro.javacard.engine.globalplatform.GPTestUtils.gpAID;
import static pro.javacard.engine.globalplatform.GPTestUtils.openIsd;

// PPSE (EMVCo PPSE and Application Management for SE v1.0): one PPSEApplet class, several instances.
// The directory instance (AID '2PAY.SYS.DDF01', GlobalRegistry) builds its FCI from the discretionary
// data of activated financial applications; payment instances are the same class, set their own
// discretionary data via INS_UPDATE_DD, and are enumerated through getNextGPCLRegistryEntry.
public class PPSETest {

    private static final AID PKG = AIDUtil.create("0102030405");
    private static final AID PPSE = AIDUtil.create("325041592E5359532E4444463031"); // '2PAY.SYS.DDF01'
    private static final AID PAY_A = AIDUtil.create("D23300000077AA01");
    private static final AID PAY_B = AIDUtil.create("D23300000077BB01"); // AID > PAY_A: enumerated after it
    private static final AID PAY_C = AIDUtil.create("D23300000077CC01"); // non-financial, must be excluded

    private static final byte AFI_FINANCIAL = 0x20;
    private static final byte AFI_OTHER = 0x30;

    private static final byte INS_UPDATE_DD = (byte) 0xDA;
    private static final byte INS_PUT_TEMPLATE = (byte) 0xD2;
    private static final byte INS_SET_MODE = (byte) 0xD6;
    private static final byte MODE_EXTERNAL = (byte) 0x01;
    private static final byte MODE_MUTEX = (byte) 0x03;

    private static JavaCardEngine freshEngine() {
        var sim = new JavaCardEngine.Builder().build();
        sim.loadApplet(PKG, PPSE, PPSEApplet.class);
        sim.loadApplet(PKG, PAY_A, PPSEApplet.class);
        sim.loadApplet(PKG, PAY_B, PPSEApplet.class);
        sim.loadApplet(PKG, PAY_C, PPSEApplet.class);
        return sim;
    }

    // Two activated financial apps set their discretionary data at runtime; the directory merges both.
    @Test
    public void directoryFromRuntimeUpdates() throws Exception {
        var sim = freshEngine();
        var dirA = dirEntry(PAY_A, "A", 0x01);
        var dirB = dirEntry(PAY_B, "B", 0x02);

        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            installDirectory(gp);
            installPayment(gp, PAY_A, AFI_FINANCIAL, null);
            installPayment(gp, PAY_B, AFI_FINANCIAL, null);
        }
        try (var bibo = sim.connect()) {
            selectAID(bibo, PAY_A);
            updateDD(bibo, bf0c(dirA));
            selectAID(bibo, PAY_B);
            updateDD(bibo, bf0c(dirB));
        }
        try (var bibo = sim.connect()) {
            assertArrayEquals(expectedFci(dirA, dirB), selectAID(bibo, PPSE));
        }
    }

    // Initial directory entry seeded via the INSTALL A6 parameter, then replaced via INS_UPDATE_DD.
    @Test
    public void installSeedThenRuntimeUpdate() throws Exception {
        var sim = freshEngine();
        var v1 = dirEntry(PAY_A, "1", 0x01);
        var v2 = dirEntry(PAY_A, "2", 0x01);

        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            installDirectory(gp);
            installPayment(gp, PAY_A, AFI_FINANCIAL, v1); // A6 seed
        }
        try (var bibo = sim.connect()) {
            assertArrayEquals(expectedFci(v1), selectAID(bibo, PPSE));
        }
        try (var bibo = sim.connect()) {
            selectAID(bibo, PAY_A);
            updateDD(bibo, bf0c(v2));
        }
        try (var bibo = sim.connect()) {
            assertArrayEquals(expectedFci(v2), selectAID(bibo, PPSE));
        }
    }

    // A non-financial activated app with discretionary data is filtered out by AFI_FINANCIAL.
    @Test
    public void nonFinancialAppExcluded() throws Exception {
        var sim = freshEngine();
        var dirA = dirEntry(PAY_A, "A", 0x01);
        var dirC = dirEntry(PAY_C, "C", 0x01);

        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            installDirectory(gp);
            installPayment(gp, PAY_A, AFI_FINANCIAL, dirA);
            installPayment(gp, PAY_C, AFI_OTHER, dirC);
        }
        try (var bibo = sim.connect()) {
            assertArrayEquals(expectedFci(dirA), selectAID(bibo, PPSE));
        }
    }

    // No activated payment apps: Table 3-4 form, the bare 6F { 84 '2PAY.SYS.DDF01' }.
    @Test
    public void emptyDirectory() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            installDirectory(openIsd(bibo));
        }
        try (var bibo = sim.connect()) {
            byte[] expected = TLV.of(Tag.ber(0x6F), TLV.of(Tag.ber(0x84), AIDUtil.bytes(PPSE))).encode();
            assertArrayEquals(expected, selectAID(bibo, PPSE));
        }
    }

    // CREL restricted view (GPC CL): a PPSE without GLOBAL REGISTRY still enumerates the applications
    // that name it in their CREL list. This is the Internal-Mode wiring (no GlobalRegistry needed).
    @Test
    public void crelRestrictedView() throws Exception {
        var sim = freshEngine();
        var dirA = dirEntry(PAY_A, "A", 0x01);
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            installDirectory(gp, EnumSet.noneOf(Privilege.class)); // no GlobalRegistry
            installPayment(gp, PAY_A, AFI_FINANCIAL, dirA, PPSE);  // PAY_A references PPSE as a CREL
        }
        try (var bibo = sim.connect()) {
            assertArrayEquals(expectedFci(dirA), selectAID(bibo, PPSE));
        }
    }

    // No registry role: a PPSE without GLOBAL REGISTRY that no application references as a CREL is denied
    // by the registry (SW_CONDITIONS_NOT_SATISFIED), which the applet renders as the empty Table 3-4 FCI.
    @Test
    public void unauthorizedCallerSeesEmptyDirectory() throws Exception {
        var sim = freshEngine();
        var dirA = dirEntry(PAY_A, "A", 0x01);
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            installDirectory(gp, EnumSet.noneOf(Privilege.class)); // no GlobalRegistry, not a CREL of anything
            installPayment(gp, PAY_A, AFI_FINANCIAL, dirA);        // PAY_A does NOT reference PPSE
        }
        try (var bibo = sim.connect()) {
            byte[] empty = TLV.of(Tag.ber(0x6F), TLV.of(Tag.ber(0x84), AIDUtil.bytes(PPSE))).encode();
            assertArrayEquals(empty, selectAID(bibo, PPSE));
        }
    }

    // External mode: the device pushes a ready-made FCI Proprietary Template; SELECT returns it verbatim.
    @Test
    public void externalModeReturnsStoredTemplate() throws Exception {
        var sim = freshEngine();
        TLV a5 = TLV.of(Tag.ber(0xA5), TLV.of(Tag.ber(0xBF0C), dirEntry(PAY_A, "X", 0x01)));
        try (var bibo = sim.connect()) {
            installDirectory(openIsd(bibo)); // External does not enumerate; privilege is irrelevant
        }
        try (var bibo = sim.connect()) {
            selectAID(bibo, PPSE);
            setMode(bibo, MODE_EXTERNAL);
            putTemplate(bibo, a5.encode());
        }
        try (var bibo = sim.connect()) {
            byte[] expected = TLV.of(Tag.ber(0x6F), TLV.of(Tag.ber(0x84), AIDUtil.bytes(PPSE)), a5).encode();
            assertArrayEquals(expected, selectAID(bibo, PPSE));
        }
    }

    // Mutual Exclusivity: activating B while A is active deactivates A, so the FCI lists only B (R3.12.2).
    @Test
    public void mutualExclusivityDeactivatesPrevious() throws Exception {
        var sim = freshEngine();
        var dirA = dirEntry(PAY_A, "A", 0x01);
        var dirB = dirEntry(PAY_B, "B", 0x02);
        try (var bibo = sim.connect()) {
            installDirectory(openIsd(bibo), EnumSet.noneOf(Privilege.class)); // PPSE acts purely as a CREL
        }
        try (var bibo = sim.connect()) {
            selectAID(bibo, PPSE);
            setMode(bibo, MODE_MUTEX);
        }
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            installPayment(gp, PAY_A, AFI_FINANCIAL, dirA, PPSE);
            installPayment(gp, PAY_B, AFI_FINANCIAL, dirB, PPSE); // activating B deactivates A
        }
        try (var bibo = sim.connect()) {
            assertArrayEquals(expectedFci(dirB), selectAID(bibo, PPSE));
        }
    }

    // SET MODE rejects an unsupported mode value.
    @Test
    public void setModeRejectsInvalid() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            installDirectory(openIsd(bibo));
        }
        try (var bibo = sim.connect()) {
            selectAID(bibo, PPSE);
            var r = bibo.transmit(new CommandAPDU(0x80, INS_SET_MODE, 0x04, 0x00));
            assertEquals(0x6A86, r.getSW());
        }
    }

    private static void setMode(BIBO bibo, byte mode) {
        var r = bibo.transmit(new CommandAPDU(0x80, INS_SET_MODE, mode, 0x00));
        assertEquals(0x9000, r.getSW());
    }

    private static void putTemplate(BIBO bibo, byte[] a5) {
        var r = bibo.transmit(new CommandAPDU(0x80, INS_PUT_TEMPLATE, 0x01, 0x00, a5));
        assertEquals(0x9000, r.getSW());
    }

    private static void installDirectory(GPSession gp) throws Exception {
        installDirectory(gp, EnumSet.of(Privilege.GlobalRegistry));
    }

    private static void installDirectory(GPSession gp, EnumSet<Privilege> privs) throws Exception {
        gp.installAndMakeSelectable(gpAID(PKG), gpAID(PPSE), gpAID(PPSE), privs, new byte[0]);
    }

    private static void installPayment(GPSession gp, AID aid, byte family, TLV initialDir) throws Exception {
        installPayment(gp, aid, family, initialDir, null);
    }

    // Activated app of the given family; optional CREL reference (A3) and A6 seed = BF0C { initialDir }.
    private static void installPayment(GPSession gp, AID aid, byte family, TLV initialDir, AID crel) throws Exception {
        var a1 = new ArrayList<TLV>();
        a1.add(TLV.of(Tag.ber(0x87), new byte[]{family}));
        if (crel != null) {
            a1.add(TLV.of(Tag.ber(0xA3), TLV.of(Tag.ber(0x4F), AIDUtil.bytes(crel))));
        }
        if (initialDir != null) {
            a1.add(TLV.of(Tag.ber(0xA6), TLV.of(Tag.ber(0xBF0C), initialDir)));
        }
        TLV a0 = TLV.of(Tag.ber(0xA0), TLV.of(Tag.ber(0x81), new byte[]{0x01})); // STATE_CL_ACTIVATED
        TLV ef = TLV.of(Tag.ber(0xEF), a0, TLV.of(Tag.ber(0xA1), a1.toArray(new TLV[0])));
        byte[] params = TLV.encode(TLV.of(Tag.ber(0xC9), new byte[]{0x00}), ef);
        gp.installAndMakeSelectable(gpAID(PKG), gpAID(aid), gpAID(aid), EnumSet.noneOf(Privilege.class), params);
    }

    private static TLV dirEntry(AID aid, String label, int priority) {
        return TLV.of(Tag.ber(0x61),
                TLV.of(Tag.ber(0x4F), AIDUtil.bytes(aid)),
                TLV.of(Tag.ber(0x50), label.getBytes(StandardCharsets.US_ASCII)),
                TLV.of(Tag.ber(0x87), new byte[]{(byte) priority}));
    }

    private static byte[] bf0c(TLV dir) {
        return TLV.of(Tag.ber(0xBF0C), dir).encode();
    }

    private static byte[] expectedFci(TLV... dirs) {
        TLV name = TLV.of(Tag.ber(0x84), AIDUtil.bytes(PPSE));
        TLV a5 = TLV.of(Tag.ber(0xA5), TLV.of(Tag.ber(0xBF0C), dirs));
        return TLV.of(Tag.ber(0x6F), name, a5).encode();
    }

    private static void updateDD(BIBO bibo, byte[] dd) {
        var r = bibo.transmit(new CommandAPDU(0x80, INS_UPDATE_DD, 0x00, 0x00, dd));
        assertEquals(0x9000, r.getSW());
    }

    private static byte[] selectAID(BIBO bibo, AID aid) {
        var r = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AIDUtil.bytes(aid), 256));
        assertEquals(0x9000, r.getSW());
        return r.getData();
    }
}
