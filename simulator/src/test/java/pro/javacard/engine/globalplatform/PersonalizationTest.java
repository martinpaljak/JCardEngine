// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.samples.HelloWorldApplet;
import com.licel.jcardsim.utils.AIDUtil;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.engine.testapplets.GlobalPlatformTestApplet;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPRegistryEntry;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.keys.PlaintextKeys;

import java.security.SecureRandom;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static pro.javacard.engine.globalplatform.GPTestUtils.gpAID;

// Single end-to-end narrative covering indirect personalization (GPC v2.3.1 11.5.2.3.6 INSTALL
// [for personalization], 11.11 STORE DATA) and the JCRE context switch into the target applet
// during Personalization.processData(). GPC v2.3.1 7.3.2: "the command is forwarded to the
// Application by the GlobalPlatform Trusted Framework which handles inter-application
// communication between Security Domains and Applications". Replaces IndirectPersonalizationTest.
// Read-back of the captured payload, JCSystem.getAID() and JCSystem.getPreviousContextAID() is
// driven by the test applet's own INS protocol (gp-pro does not expose application-level SELECT
// for arbitrary applets).
public class PersonalizationTest {

    @Test
    public void indirectPersonalizationContextSwitchAndReadBack() throws Exception {
        var sim = JavaCardEngine.create();

        var appletAID = AIDUtil.create("0A0B0C0D0E0F101112");
        var jcaid = gpAID(appletAID);
        var appletAIDBytes = AIDUtil.bytes(appletAID);
        var isdAIDBytes = AIDUtil.bytes(SecurityDomainApplet.OPEN_AID);

        sim.loadApplet(appletAID, appletAID, GlobalPlatformTestApplet.class);

        try (var bibo = sim.connect()) {
            // 1. Open ISD ENC session and INSTALL [for install and make selectable] (GPC v2.3.1
            // 11.5.2.3.2, Table 11-43).
            var gp = GPSession.discover(bibo);
            gp.openSecureChannel(PlaintextKeys.defaultKey(), null, null, EnumSet.of(GPSession.APDUMode.ENC));
            gp.installAndMakeSelectable(jcaid, jcaid, jcaid, EnumSet.noneOf(GPRegistryEntry.Privilege.class), new byte[4]);

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

            // 5. SELECT the applet via raw APDU — gp-pro does not expose application-level SELECT
            // for arbitrary applets, and the test-applet INS protocol below requires it selected.
            var select = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, appletAIDBytes, 256));
            assertEquals(0x9000, select.getSW(), "SELECT of installed applet must succeed (GPC v2.3.1 11.9)");

            // 6. INS_PERSO_DATA: read back the STORE DATA payload captured by processData().
            var read = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_PERSO_DATA, 0x00, 0x00, 256));
            assertEquals(0x9000, read.getSW());
            assertArrayEquals(persoData, read.getData(), "captured STORE DATA payload must match what was sent (GPC v2.3.1 11.11)");

            // 7. INS_PERSO_AID: JCSystem.getAID() captured during processData() must be the
            // target's own AID, proving the JCRE context switch (GPC v2.3.1 7.3.2).
            var aidResp = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_PERSO_AID, 0x00, 0x00, 256));
            assertEquals(0x9000, aidResp.getSW());
            assertArrayEquals(appletAIDBytes, aidResp.getData(), "JCSystem.getAID() during processData() must return the target applet's AID (GPC v2.3.1 7.3.2)");

            // 8. INS_PERSO_PREVAID: JCSystem.getPreviousContextAID() captured during processData()
            // must be the invoking SD (the ISD here) — completing the context-switch contract.
            var prevAidResp = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_PERSO_PREVAID, 0x00, 0x00, 256));
            assertEquals(0x9000, prevAidResp.getSW());
            assertArrayEquals(isdAIDBytes, prevAidResp.getData(), "JCSystem.getPreviousContextAID() during processData() must return the invoking SD AID (GPC v2.3.1 7.3.2)");
        }
    }

    // INSTALL [for personalization] only succeeds when the target implements Personalization or
    // Application per the rule in GPC v2.3.1 7.3.2 with SW codes drawn from 11.5.3.2 / Table 11-55,
    // so HelloWorldApplet (which implements neither) must be rejected with SW_WRONG_DATA (6A80)
    // and the malformed-payload probe additionally exercises the SD's INSTALL P1 dispatch and
    // payload validation path.
    @Test
    public void nonPersonalizableAppletRejected() throws Exception {
        var sim = JavaCardEngine.create();

        var appletAID = AIDUtil.create("0A0B0C0D0E0F101112");
        var jcaid = gpAID(appletAID);

        sim.loadApplet(appletAID, appletAID, HelloWorldApplet.class);

        try (var bibo = sim.connect()) {
            var gp = GPSession.discover(bibo);
            gp.openSecureChannel(PlaintextKeys.defaultKey(), null, null, EnumSet.of(GPSession.APDUMode.ENC));
            gp.installAndMakeSelectable(jcaid, jcaid, jcaid, EnumSet.noneOf(GPRegistryEntry.Privilege.class), new byte[4]);

            gp = GPSession.discover(bibo);
            gp.openSecureChannel(PlaintextKeys.defaultKey(), null, null, EnumSet.of(GPSession.APDUMode.ENC));

            // Malformed INSTALL [for personalization] payload — SD must reject with 6A80 before
            // dispatching to the target.
            var malformed = gp.transmit(new CommandAPDU(GPSession.CLA_GP, GPSession.INS_INSTALL, 0x20, 0x00, new byte[]{0x01}, 256));
            assertEquals(0x6A80, malformed.getSW(), "malformed INSTALL [for personalization] payload must be rejected with SW_WRONG_DATA (6A80) per GPC v2.3.1 11.5.3.2 / Table 11-55");

            // Well-formed INSTALL [for personalization] against an applet that implements neither
            // Personalization nor Application must yield 6A80 per GPC v2.3.1 11.5.3.2.
            var finalGp = gp;
            var ex = assertThrows(GPException.class, () -> finalGp.installForPersonalization(jcaid));
            assertEquals(0x6A80, ex.sw, "INSTALL [for personalization] of an applet implementing neither Personalization nor Application must yield SW_WRONG_DATA (6A80) per GPC v2.3.1 7.3.2 + 11.5.3.2 / Table 11-55");
        }
    }
}
