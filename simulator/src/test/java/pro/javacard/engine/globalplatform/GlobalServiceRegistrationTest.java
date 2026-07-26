// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.testng.annotations.Test;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.engine.testapplets.GlobalServiceTestApplet;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPSession;
import pro.javacard.tlv.TLV;

import java.util.EnumSet;

import static org.testng.Assert.*;
import static pro.javacard.engine.globalplatform.GPTestUtils.gpAID;
import static pro.javacard.engine.globalplatform.GPTestUtils.openIsd;

// Global Service registration (GPC v2.3.1 8.1.1), including install-time CB Global Service Parameters.
public class GlobalServiceRegistrationTest {

    private static final AID PKG = AIDUtil.create("01020304050607080F");
    private static final AID A = GPTestUtils.test_aid("9001");
    private static final AID B = GPTestUtils.test_aid("9002");

    private static final byte SVC_CLA = (byte) 0x80;
    private static final byte SVC_INS = (byte) 0xEE;
    private static final byte P1_REGISTER = (byte) 0x01;
    private static final byte P1_DEREGISTER = (byte) 0x02;

    // GPC v2.3.1 8.1.3: 0x8101 = GP Secure Channel family, id 01; 0x8100 = the family-only form.
    private static final byte[] SVC_8101 = {(byte) 0x81, 0x01};
    private static final byte[] SVC_8102 = {(byte) 0x81, 0x02};
    private static final byte[] SVC_8100 = {(byte) 0x81, 0x00};

    // No CB recorded: any service name may be registered, then deregistered (8.1.1).
    @Test
    public void registerWithoutInstalledNames() throws Exception {
        var sim = engine(A);
        try (var bibo = sim.connect()) {
            install(openIsd(bibo), A, null);
        }
        try (var bibo = sim.connect()) {
            assertOk(register(bibo, A, SVC_8101));
        }
        try (var bibo = sim.connect()) {
            assertOk(deregister(bibo, A, SVC_8101));
        }
        // Deregister of an unregistered name fails (8.1.1: must be registered in own entry).
        try (var bibo = sim.connect()) {
            assertSw(0x6985, deregister(bibo, A, SVC_8101));
        }
    }

    // Missing Global Service privilege -> rejected (8.1.1 step a). 6982.
    @Test
    public void registerWithoutPrivilege() throws Exception {
        var sim = engine(A);
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            gp.installAndMakeSelectable(gpAID(PKG), gpAID(A), gpAID(A), EnumSet.noneOf(Privilege.class), new byte[0]);
        }
        try (var bibo = sim.connect()) {
            assertSw(0x6982, register(bibo, A, SVC_8101));
        }
    }

    // CB recorded an exact name: that name registers; an unrelated name is rejected (8.1.1 step b).
    @Test
    public void installedNameConstrainsRegistration() throws Exception {
        var sim = engine(A);
        try (var bibo = sim.connect()) {
            install(openIsd(bibo), A, SVC_8101);
        }
        try (var bibo = sim.connect()) {
            assertOk(register(bibo, A, SVC_8101));
        }
        try (var bibo = sim.connect()) {
            assertSw(0x6985, register(bibo, A, SVC_8102));
        }
    }

    // CB recorded a family-only name (id 00): any name in that family registers (8.1.1 step b).
    @Test
    public void familyOnlyRecordMatchesAnyId() throws Exception {
        var sim = engine(A);
        try (var bibo = sim.connect()) {
            install(openIsd(bibo), A, SVC_8100);
        }
        try (var bibo = sim.connect()) {
            assertOk(register(bibo, A, SVC_8101));
        }
        try (var bibo = sim.connect()) {
            assertOk(register(bibo, A, SVC_8102));
        }
    }

    // Cross-entry uniqueness: a name uniquely registered by A cannot be registered by B (8.1.1
    // step c); after A deregisters, B may register it.
    @Test
    public void uniquenessAcrossEntries() throws Exception {
        var sim = engine(A, B);
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            install(gp, A, null);
            install(gp, B, null);
        }
        try (var bibo = sim.connect()) {
            assertOk(register(bibo, A, SVC_8101));
        }
        try (var bibo = sim.connect()) {
            assertSw(0x6985, register(bibo, B, SVC_8101));
        }
        try (var bibo = sim.connect()) {
            assertOk(deregister(bibo, A, SVC_8101));
        }
        try (var bibo = sim.connect()) {
            assertOk(register(bibo, B, SVC_8101));
        }
    }

    // ------------------- helpers ------------------- //

    private static JavaCardEngine engine(AID... aids) {
        var sim = new JavaCardEngine.Builder().build();
        for (var aid : aids) {
            sim.loadApplet(PKG, aid, GlobalServiceTestApplet.class);
        }
        return sim;
    }

    // INSTALL the service applet with the Global Service privilege; optional CB Global Service
    // Parameters in the EF block. Leading empty C9 stops GPSession from re-wrapping the payload.
    private static void install(GPSession gp, AID aid, byte[] cbName) throws Exception {
        byte[] params;
        if (cbName == null) {
            params = new byte[0];
        } else {
            var ef = TLV.build(0xEF).add(0xCB, cbName);
            params = TLV.encode(TLV.of(0xC9, new byte[0]), ef);
        }
        gp.installAndMakeSelectable(gpAID(PKG), gpAID(aid), gpAID(aid), EnumSet.of(Privilege.GlobalService), params);
    }

    private static byte[] register(BIBO bibo, AID aid, byte[] name) {
        return call(bibo, aid, P1_REGISTER, name);
    }

    private static byte[] deregister(BIBO bibo, AID aid, byte[] name) {
        return call(bibo, aid, P1_DEREGISTER, name);
    }

    private static byte[] call(BIBO bibo, AID aid, byte p1, byte[] name) {
        bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AIDUtil.bytes(aid), 256));
        var resp = bibo.transmit(new CommandAPDU(SVC_CLA, SVC_INS, p1, 0x00, name, 256));
        assertEquals(resp.getSW(), 0x9000);
        return resp.getData();
    }

    // Success response: a single 0x01 byte.
    private static void assertOk(byte[] data) {
        assertEquals(data, new byte[]{0x01});
    }

    // Failure response: the 2-byte SW that registerService/deregisterService threw.
    private static void assertSw(int sw, byte[] data) {
        assertEquals(data.length, 2);
        assertEquals(((data[0] & 0xFF) << 8) | (data[1] & 0xFF), sw);
    }
}
