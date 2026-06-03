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

import java.nio.charset.StandardCharsets;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.*;

public class PPSETest {

    private static final AID PKG = AIDUtil.create("0102030405");
    private static final AID PPSE = AIDUtil.create("325041592E5359532E4444463031"); // '2PAY.SYS.DDF01'
    private static final AID PAY_A = GPTestUtils.test_aid("AA01");
    private static final AID PAY_B = GPTestUtils.test_aid("BB01");

    private static final byte AFI_FINANCIAL = 0x20;
    private static final byte INS_UPDATE_DD = (byte) 0xDA;

    private static JavaCardEngine freshEngine() {
        var sim = new JavaCardEngine.Builder().build();
        sim.loadApplet(PKG, PPSE, PPSEApplet.class);
        sim.loadApplet(PKG, PAY_A, PaymentApplet.class);
        sim.loadApplet(PKG, PAY_B, PaymentApplet.class);
        return sim;
    }

    @Test
    public void directoryFromActivatedApp() throws Exception {
        var sim = freshEngine();
        var v1 = dirEntry(PAY_A, "1", 0x01);
        var v2 = dirEntry(PAY_A, "X".repeat(130), 0x01); // pushes the body past the BER short-form length

        try (var bibo = sim.connect()) {
            var gp = GPTestUtils.openIsd(bibo);
            installDirectory(gp);
            installPayment(gp, PAY_A, v1);
        }
        try (var bibo = sim.connect()) {
            assertArrayEquals(expectedFci(v1), selectAID(bibo, PPSE));
        }
        try (var bibo = sim.connect()) {
            selectAID(bibo, PAY_A);
            updateDD(bibo, bf0c(v2));
        }
        try (var bibo = sim.connect()) {
            byte[] fci = selectAID(bibo, PPSE);
            assertTrue(fci.length > 127);
            assertArrayEquals(expectedFci(v2), fci);
        }
    }

    @Test
    public void latestActivatedWins() throws Exception {
        var sim = freshEngine();
        var dirA = dirEntry(PAY_A, "A", 0x01);
        var dirB = dirEntry(PAY_B, "B", 0x02);

        try (var bibo = sim.connect()) {
            installDirectory(GPTestUtils.openIsd(bibo));
        }
        try (var bibo = sim.connect()) {
            assertArrayEquals(bareFci(), selectAID(bibo, PPSE));
        }
        try (var bibo = sim.connect()) {
            var gp = GPTestUtils.openIsd(bibo);
            installPayment(gp, PAY_A, dirA);
            installPayment(gp, PAY_B, dirB);
        }
        try (var bibo = sim.connect()) {
            assertArrayEquals(expectedFci(dirB), selectAID(bibo, PPSE));
        }
    }

    private static void installDirectory(GPSession gp) throws Exception {
        gp.installAndMakeSelectable(GPTestUtils.gpAID(PKG), GPTestUtils.gpAID(PPSE), GPTestUtils.gpAID(PPSE), EnumSet.noneOf(Privilege.class), new byte[0]);
    }

    private static void installPayment(GPSession gp, AID aid, TLV initialDir) throws Exception {
        var a1 = TLV.build(0xA1)
                .add(0x87, new byte[]{AFI_FINANCIAL})
                .add(TLV.build(0xA3).add(0x4F, AIDUtil.bytes(PPSE)))
                .add(TLV.build(0xA6).add(TLV.build(0xBF0C).add(initialDir)));
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

    private static byte[] expectedFci(TLV dir) {
        var a5 = TLV.build(0xA5).add(TLV.build(0xBF0C).add(dir));
        return TLV.build(0x6F).add(0x84, AIDUtil.bytes(PPSE)).add(a5).encode();
    }

    private static byte[] bareFci() {
        return TLV.build(0x6F).add(0x84, AIDUtil.bytes(PPSE)).encode();
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
