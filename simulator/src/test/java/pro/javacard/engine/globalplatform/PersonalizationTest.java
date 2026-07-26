// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.samples.HelloWorldApplet;
import com.licel.jcardsim.utils.AIDUtil;
import org.testng.annotations.Test;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.engine.testapplets.GlobalPlatformTestApplet;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPRegistryEntry;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.keys.PlaintextKeys;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.EnumSet;

import static org.testng.Assert.*;
import static pro.javacard.engine.globalplatform.GPTestUtils.gpAID;
import static pro.javacard.engine.globalplatform.GPTestUtils.openIsd;

// INSTALL [for personalization] and STORE DATA forwarding, plus the standalone INSTALL [for install] / [for make selectable] flow.
public class PersonalizationTest {

    @Test
    public void indirectPersonalizationContextSwitchAndReadBack() throws Exception {
        var sim = JavaCardEngine.create();

        // ELF and instance AIDs must differ (GPC v2.3.1 6.5.1.1); instance = ELF + instance byte.
        var pkgAID = AIDUtil.create("0A0B0C0D0E0F101112");
        var appletAID = AIDUtil.create("0A0B0C0D0E0F10111201");
        var jcaid = gpAID(appletAID);
        var appletAIDBytes = AIDUtil.bytes(appletAID);
        var isdAIDBytes = AIDUtil.bytes(SecurityDomainApplet.OPEN_AID);

        sim.loadApplet(pkgAID, appletAID, GlobalPlatformTestApplet.class);

        try (var bibo = sim.connect()) {
            // 1. Open ISD ENC session and INSTALL [for install and make selectable] (GPC v2.3.1
            // 11.5.2.3.2, Table 11-43).
            var gp = GPSession.discover(bibo);
            gp.openSecureChannel(PlaintextKeys.defaultKey(), null, null, EnumSet.of(GPSession.APDUMode.ENC));
            gp.installAndMakeSelectable(gpAID(pkgAID), jcaid, jcaid, EnumSet.noneOf(GPRegistryEntry.Privilege.class), new byte[4]);

            // 2. Reopen ISD ENC session for the personalization sequence.
            gp = GPSession.discover(bibo);
            gp.openSecureChannel(PlaintextKeys.defaultKey(), null, null, EnumSet.of(GPSession.APDUMode.ENC));

            // 3. INSTALL [for personalization] (GPC v2.3.1 11.5.2.3.6, Table 11-47).
            gp.installForPersonalization(jcaid);

            // 4. STORE DATA with a >0x7F payload to catch any missing & 0xFF in length handling
            // (GPC v2.3.1 11.11). Payload is captured by the applet for read-back below.
            var persoData = new byte[217];
            SecureRandom.getInstanceStrong().nextBytes(persoData);
            gp.storeData(persoData, 0x00);

            // 5. SELECT the applet via raw APDU - gp-pro does not expose application-level SELECT
            // for arbitrary applets, and the test-applet INS protocol below requires it selected.
            var select = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, appletAIDBytes, 256));
            assertEquals(select.getSW(), 0x9000);

            // 6. INS_PERSO_DATA: read back the STORE DATA payload captured by processData().
            var read = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_PERSO_DATA, 0x00, 0x00, 256));
            assertEquals(read.getSW(), 0x9000);
            assertEquals(read.getData(), persoData);

            // 7. INS_PERSO_AID: JCSystem.getAID() captured during processData() must be the
            // target's own AID, proving the JCRE context switch (GPC v2.3.1 7.3.2).
            var aidResp = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_PERSO_AID, 0x00, 0x00, 256));
            assertEquals(aidResp.getSW(), 0x9000);
            assertEquals(aidResp.getData(), appletAIDBytes);

            // 8. INS_PERSO_PREVAID: JCSystem.getPreviousContextAID() captured during processData()
            // must be the invoking SD (the ISD here) - completing the context-switch contract.
            var prevAidResp = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_PERSO_PREVAID, 0x00, 0x00, 256));
            assertEquals(prevAidResp.getSW(), 0x9000);
            assertEquals(prevAidResp.getData(), isdAIDBytes);
        }
    }

    @Test
    public void nonPersonalizableAppletRejected() throws Exception {
        var sim = JavaCardEngine.create();

        // ELF and instance AIDs must differ (GPC v2.3.1 6.5.1.1); instance = ELF + instance byte.
        var pkgAID = AIDUtil.create("0A0B0C0D0E0F101112");
        var appletAID = AIDUtil.create("0A0B0C0D0E0F10111201");
        var jcaid = gpAID(appletAID);

        sim.loadApplet(pkgAID, appletAID, HelloWorldApplet.class);

        try (var bibo = sim.connect()) {
            var gp = GPSession.discover(bibo);
            gp.openSecureChannel(PlaintextKeys.defaultKey(), null, null, EnumSet.of(GPSession.APDUMode.ENC));
            gp.installAndMakeSelectable(gpAID(pkgAID), jcaid, jcaid, EnumSet.noneOf(GPRegistryEntry.Privilege.class), new byte[4]);

            gp = GPSession.discover(bibo);
            gp.openSecureChannel(PlaintextKeys.defaultKey(), null, null, EnumSet.of(GPSession.APDUMode.ENC));

            // Malformed INSTALL [for personalization] payload - SD must reject with 6A80 before
            // dispatching to the target.
            var malformed = gp.transmit(new CommandAPDU(GPSession.CLA_GP, GPSession.INS_INSTALL, 0x20, 0x00, new byte[]{0x01}, 256));
            assertEquals(malformed.getSW(), 0x6A80);

            // Well-formed INSTALL [for personalization] against an applet that implements neither
            // Personalization nor Application must yield 6A80 per GPC v2.3.1 11.5.3.2.
            var finalGp = gp;
            var ex = expectThrows(GPException.class, () -> finalGp.installForPersonalization(jcaid));
            assertEquals(ex.sw, 0x6A80);
        }
    }

    @Test
    public void installOnlyThenStandaloneMakeSelectable() throws Exception {
        var sim = JavaCardEngine.create();

        var pkgAID = AIDUtil.create("0A0B0C0D0E0F101112");
        var appletAID = AIDUtil.create("0A0B0C0D0E0F10111201");
        var jcaid = gpAID(appletAID);
        var pkgBytes = AIDUtil.bytes(pkgAID);
        var appletBytes = AIDUtil.bytes(appletAID);

        sim.loadApplet(pkgAID, appletAID, GlobalPlatformTestApplet.class);

        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);

            // gp-pro's GPSession exposes only the combined 0x0C install, so both INSTALL APDUs are hand-built and sent through the MAC session.
            // INSTALL [for install] only (Table 11-43): ELF | module | instance | privileges | C9 params | token.
            var installOnly = lv(pkgBytes, appletBytes, appletBytes, new byte[]{0x00}, new byte[]{(byte) 0xC9, 0x00}, new byte[0]);
            var r1 = gp.transmit(new CommandAPDU(GPSession.CLA_GP, GPSession.INS_INSTALL, GPSession.P1_INSTALL_FOR_INSTALL, 0x00, installOnly, 256));
            assertEquals(r1.getSW(), 0x9000);
            // Install without the make selectable bit leaves the applet INSTALLED (GPC v2.3.1 11.1.1 Table 11-4).
            assertEquals(appletLifeCycle(gp, jcaid), 0x03);

            // Fresh session for the make selectable phase - GPSession caches getRegistry() until its own
            // mutators dirty it, and a hand-built transmit() does not, so a new session forces a re-read.
            gp = openIsd(bibo);

            // Standalone INSTALL [for make selectable] (Table 11-44): empty | empty | App AID | privileges | params | token.
            var makeSel = lv(new byte[0], new byte[0], appletBytes, new byte[]{0x00}, new byte[0], new byte[0]);
            var r2 = gp.transmit(new CommandAPDU(GPSession.CLA_GP, GPSession.INS_INSTALL, GPSession.P1_INSTALL_FOR_MAKE_SELECTABLE, 0x00, makeSel, 256));
            assertEquals(r2.getSW(), 0x9000);
            // Make selectable promotes INSTALLED -> SELECTABLE (GPC v2.3.1 9.3.7 / 5.3.1.2).
            assertEquals(appletLifeCycle(gp, jcaid), 0x07);
        }
    }

    // LV-encode INSTALL data fields (GPC v2.3.1 11.5.2.3.x): each field as a 1-byte length prefix + value.
    private static byte[] lv(byte[]... fields) {
        var bo = new ByteArrayOutputStream();
        for (var f : fields) {
            bo.write(f.length);
            bo.writeBytes(f);
        }
        return bo.toByteArray();
    }

    // Current lifecycle byte of the named applet, read back over GET STATUS via gp.getRegistry().
    private static int appletLifeCycle(GPSession gp, pro.javacard.capfile.AID aid) throws GPException {
        return gp.getRegistry().allApplets().stream().filter(e -> e.getAID().equals(aid)).findFirst().orElseThrow().getLifeCycle() & 0xFF;
    }
}
