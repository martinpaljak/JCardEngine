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
import pro.javacard.engine.testapplets.PaymentApplet;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPSession;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.Tag;

import java.nio.charset.StandardCharsets;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.*;

// PPSE (EMVCo PPSE and Application Management for SE v1.0). The PPSEApplet directory instance (AID
// '2PAY.SYS.DDF01', GlobalRegistry) builds its FCI from the discretionary data of activated financial
// applications; the PaymentApplet instances set their own discretionary data via INS_UPDATE_DD and are
// enumerated through getNextGPCLRegistryEntry.
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
    private static final byte INS_GET_TEMPLATE = (byte) 0xD4;
    private static final byte INS_SET_MODE = (byte) 0xD6;
    private static final byte MODE_EXTERNAL = (byte) 0x01;
    private static final byte MODE_MUTEX = (byte) 0x03;

    private static JavaCardEngine freshEngine() {
        var sim = new JavaCardEngine.Builder().build();
        sim.loadApplet(PKG, PPSE, PPSEApplet.class);
        sim.loadApplet(PKG, PAY_A, PaymentApplet.class);
        sim.loadApplet(PKG, PAY_B, PaymentApplet.class);
        sim.loadApplet(PKG, PAY_C, PaymentApplet.class);
        return sim;
    }

    // Two activated financial apps set their discretionary data at runtime; the directory merges both.
    // The labels push the merged body over 127 bytes (exercising BER long-form lengths), and PAY_B's
    // BF0C over-claims its length: the directory must still copy only PAY_B's own bytes, never PAY_A's
    // larger leftover in the shared scratch buffer.
    @Test
    public void directoryFromRuntimeUpdates() throws Exception {
        var sim = freshEngine();
        var dirA = dirEntry(PAY_A, "A".repeat(80), 0x01); // larger, enumerated first
        var dirB = dirEntry(PAY_B, "B".repeat(40), 0x02);

        try (var bibo = sim.connect()) {
            var gp = GPTestUtils.openIsd(bibo);
            installDirectory(gp);
            installPayment(gp, PAY_A, AFI_FINANCIAL, null);
            installPayment(gp, PAY_B, AFI_FINANCIAL, null);
        }
        try (var bibo = sim.connect()) {
            selectAID(bibo, PAY_A);
            updateDD(bibo, bf0c(dirA));
            selectAID(bibo, PAY_B);
            updateDD(bibo, overclaimedBf0c(dirB));
        }
        try (var bibo = sim.connect()) {
            byte[] fci = selectAID(bibo, PPSE);
            assertTrue(fci.length > 127);
            assertArrayEquals(expectedFci(dirA, dirB), fci);
        }
    }

    // Initial directory entry seeded via the INSTALL A6 parameter, then replaced via INS_UPDATE_DD.
    @Test
    public void installSeedThenRuntimeUpdate() throws Exception {
        var sim = freshEngine();
        var v1 = dirEntry(PAY_A, "1", 0x01);
        var v2 = dirEntry(PAY_A, "2", 0x01);

        try (var bibo = sim.connect()) {
            var gp = GPTestUtils.openIsd(bibo);
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
            var gp = GPTestUtils.openIsd(bibo);
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
            installDirectory(GPTestUtils.openIsd(bibo));
        }
        try (var bibo = sim.connect()) {
            byte[] expected = TLV.build(0x6F).add(0x84, AIDUtil.bytes(PPSE)).encode();
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
            var gp = GPTestUtils.openIsd(bibo);
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
            var gp = GPTestUtils.openIsd(bibo);
            installDirectory(gp, EnumSet.noneOf(Privilege.class)); // no GlobalRegistry, not a CREL of anything
            installPayment(gp, PAY_A, AFI_FINANCIAL, dirA);        // PAY_A does NOT reference PPSE
        }
        try (var bibo = sim.connect()) {
            byte[] empty = TLV.build(0x6F).add(0x84, AIDUtil.bytes(PPSE)).encode();
            assertArrayEquals(empty, selectAID(bibo, PPSE));
        }
    }

    // External mode: the device pushes a ready-made FCI Proprietary Template; SELECT returns it verbatim.
    @Test
    public void externalModeReturnsStoredTemplate() throws Exception {
        var sim = freshEngine();
        var a5 = TLV.build(0xA5).add(TLV.build(0xBF0C).add(dirEntry(PAY_A, "X", 0x01)));
        try (var bibo = sim.connect()) {
            installDirectory(GPTestUtils.openIsd(bibo)); // External does not enumerate; privilege is irrelevant
        }
        try (var bibo = sim.connect()) {
            selectAID(bibo, PPSE);
            setMode(bibo, MODE_EXTERNAL);
            putTemplate(bibo, a5.encode());
        }
        try (var bibo = sim.connect()) {
            byte[] expected = TLV.build(0x6F).add(0x84, AIDUtil.bytes(PPSE)).add(a5).encode();
            assertArrayEquals(expected, selectAID(bibo, PPSE));
            // GET TEMPLATE returns the same FCI a SELECT would (Table 3-1, R3.8.3)
            var r = bibo.transmit(new CommandAPDU(0x80, INS_GET_TEMPLATE, 0x01, 0x00));
            assertEquals(0x9000, r.getSW());
            assertArrayEquals(expected, r.getData());
        }
    }

    // Mutual Exclusivity: activating B while A is active deactivates A, so the FCI lists only B (R3.12.2).
    @Test
    public void mutualExclusivityDeactivatesPrevious() throws Exception {
        var sim = freshEngine();
        var dirA = dirEntry(PAY_A, "A", 0x01);
        var dirB = dirEntry(PAY_B, "B", 0x02);
        try (var bibo = sim.connect()) {
            installDirectory(GPTestUtils.openIsd(bibo), EnumSet.noneOf(Privilege.class)); // PPSE acts purely as a CREL
        }
        try (var bibo = sim.connect()) {
            selectAID(bibo, PPSE);
            setMode(bibo, MODE_MUTEX);
        }
        try (var bibo = sim.connect()) {
            var gp = GPTestUtils.openIsd(bibo);
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
            installDirectory(GPTestUtils.openIsd(bibo));
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
        gp.installAndMakeSelectable(GPTestUtils.gpAID(PKG), GPTestUtils.gpAID(PPSE), GPTestUtils.gpAID(PPSE), privs, new byte[0]);
    }

    private static void installPayment(GPSession gp, AID aid, byte family, TLV initialDir) throws Exception {
        installPayment(gp, aid, family, initialDir, null);
    }

    // Activated app of the given family; optional CREL reference (A3) and A6 seed = BF0C { initialDir }.
    private static void installPayment(GPSession gp, AID aid, byte family, TLV initialDir, AID crel) throws Exception {
        var a1 = TLV.build(0xA1).add(0x87, new byte[]{family});
        if (crel != null) {
            a1.add(TLV.build(0xA3).add(0x4F, AIDUtil.bytes(crel)));
        }
        if (initialDir != null) {
            a1.add(TLV.build(0xA6).add(TLV.build(0xBF0C).add(initialDir)));
        }
        var ef = TLV.build(0xEF)
                .add(TLV.build(0xA0).add(0x81, new byte[]{0x01})) // STATE_CL_ACTIVATED
                .add(a1);
        byte[] params = TLV.encode(TLV.of(0xC9, new byte[]{0x00}), ef);
        gp.installAndMakeSelectable(GPTestUtils.gpAID(PKG), GPTestUtils.gpAID(aid), GPTestUtils.gpAID(aid), EnumSet.noneOf(Privilege.class), params);
    }

    private static TLV dirEntry(AID aid, String label, int priority) {
        return TLV.build(0x61)
                .add(0x4F, AIDUtil.bytes(aid))
                .add(0x50, label.getBytes(StandardCharsets.US_ASCII))
                .add(0x87, new byte[]{(byte) priority});
    }

    private static byte[] bf0c(TLV dir) {
        return TLV.build(0xBF0C).add(dir).encode();
    }

    // BF0C whose length octet claims 0x7F bytes but carries only the real directory entry.
    private static byte[] overclaimedBf0c(TLV dir) {
        byte[] entry = dir.encode();
        byte[] out = new byte[3 + entry.length];
        out[0] = (byte) 0xBF;
        out[1] = 0x0C;
        out[2] = 0x7F;
        System.arraycopy(entry, 0, out, 3, entry.length);
        return out;
    }

    private static byte[] expectedFci(TLV... dirs) {
        var a5 = TLV.build(0xA5).add(TLV.of(Tag.ber(0xBF0C), dirs)); // Tag.ber: the only varargs spread
        return TLV.build(0x6F).add(0x84, AIDUtil.bytes(PPSE)).add(a5).encode();
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
