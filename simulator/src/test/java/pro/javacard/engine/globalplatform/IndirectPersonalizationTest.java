package pro.javacard.engine.globalplatform;

import apdu4j.core.APDUBIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.EngineSession;
import pro.javacard.engine.JavaCardEngine;
import com.licel.jcardsim.samples.HelloWorldApplet;
import pro.javacard.engine.testapplets.PersonalizationTestApplet;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPRegistryEntry;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.keys.PlaintextKeys;

import java.security.SecureRandom;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.*;


public class IndirectPersonalizationTest {

    // GP 2.2.1 Section 7.3.3: Indirect personalization - the Security Domain receives
    // STORE DATA on behalf of a target application, unwraps secure messaging, and forwards
    // the raw data to the target via Personalization.processData() or Application.processData().
    @Test
    public void testIndirectPersonalization() throws Exception {
        JavaCardEngine sim = JavaCardEngine.create();

        AID appletAID = AIDUtil.create("0A0B0C0D0E0F101112");
        pro.javacard.capfile.AID jcaid = new pro.javacard.capfile.AID(AIDUtil.bytes(appletAID));

        // Load the applet class into the GP registry
        sim.loadApplet(appletAID, appletAID, PersonalizationTestApplet.class);

        try (EngineSession instance = sim.connect()) {
            APDUBIBO bibo = new APDUBIBO(instance);

            // 1. Open secure channel to ISD, install the applet
            //    GP 2.2.1 Section 9.5.2.3.1: INSTALL [for install and make selectable]
            PlaintextKeys pk = PlaintextKeys.defaultKey();
            GPSession gp = GPSession.discover(bibo);
            gp.openSecureChannel(pk, null, null, EnumSet.of(GPSession.APDUMode.ENC));
            gp.installAndMakeSelectable(jcaid, jcaid, jcaid,
                    EnumSet.noneOf(GPRegistryEntry.Privilege.class), new byte[4]);

            // 2. Open new secure channel to ISD for personalization
            PlaintextKeys pk2 = PlaintextKeys.defaultKey();
            gp = GPSession.discover(bibo);
            gp.openSecureChannel(pk2, null, null, EnumSet.of(GPSession.APDUMode.ENC));

            // 3. INSTALL [for personalization]
            //    GP 2.2.1 Section 9.5.2.3.5: INSTALL [for personalization]
            gp.installForPersonalization(jcaid);

            // 4. STORE DATA with test payload
            //    GP 2.2.1 Section 9.7.2: STORE DATA command
            byte[] persoData = new byte[217]; // NOTE: intentionally > 0x7f to catch the missing & 0xFF.
            SecureRandom.getInstanceStrong().nextBytes(persoData);
            gp.storeData(persoData, 0x00);

            // 5. SELECT the applet and verify stored data
            ResponseAPDU select = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00,
                    AIDUtil.bytes(appletAID), 256));
            assertEquals(0x9000, select.getSW());

            // 6. Read back the personalization data (INS 0x01)
            ResponseAPDU read = bibo.transmit(new CommandAPDU(0x00, 0x01, 0x00, 0x00, 256));
            assertEquals(0x9000, read.getSW());
            assertArrayEquals(persoData, read.getData());
        }
    }

    // GP 2.2.1 Section 7.3.3 specifies that when the Security Domain forwards data via
    // Personalization.processData(), a JCRE context switch occurs to the target application.
    // This means:
    //   - JCSystem.getAID() inside processData() must return the target applet's AID
    //   - JCSystem.getPreviousContextAID() must return the Security Domain's AID
    // See also GP API Personalization interface javadoc:
    //   "Upon invocation of this method, the Java Card VM performs a context switch."
    @Test
    public void testPersonalizationContextSwitch() throws Exception {
        JavaCardEngine sim = JavaCardEngine.create();

        AID appletAID = AIDUtil.create("0A0B0C0D0E0F101112");
        pro.javacard.capfile.AID jcaid = new pro.javacard.capfile.AID(AIDUtil.bytes(appletAID));
        byte[] appletAIDBytes = AIDUtil.bytes(appletAID);
        byte[] isdAIDBytes = AIDUtil.bytes(GlobalPlatformApplet.OPEN_AID);

        sim.loadApplet(appletAID, appletAID, PersonalizationTestApplet.class);

        try (EngineSession instance = sim.connect()) {
            APDUBIBO bibo = new APDUBIBO(instance);

            // Install the applet via GP (GP 2.2.1 Section 9.5.2.3.1)
            PlaintextKeys pk = PlaintextKeys.defaultKey();
            GPSession gp = GPSession.discover(bibo);
            gp.openSecureChannel(pk, null, null, EnumSet.of(GPSession.APDUMode.ENC));
            gp.installAndMakeSelectable(jcaid, jcaid, jcaid,
                    EnumSet.noneOf(GPRegistryEntry.Privilege.class), new byte[4]);

            // Open secure channel for personalization
            PlaintextKeys pk2 = PlaintextKeys.defaultKey();
            gp = GPSession.discover(bibo);
            gp.openSecureChannel(pk2, null, null, EnumSet.of(GPSession.APDUMode.ENC));

            // INSTALL [for personalization] (GP 2.2.1 Section 9.5.2.3.5)
            gp.installForPersonalization(jcaid);

            // STORE DATA - triggers processData() on target applet (GP 2.2.1 Section 9.7.2)
            byte[] persoData = new byte[]{(byte) 0xCA, (byte) 0xFE};
            gp.storeData(persoData, 0x00);

            // SELECT the target applet
            ResponseAPDU select = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00,
                    appletAIDBytes, 256));
            assertEquals(0x9000, select.getSW());

            // INS 0x02: Read JCSystem.getAID() captured during processData()
            // GP 2.2.1 Section 7.3.3: "the JCRE performs a context switch" - getAID() must
            // return the target applet's own AID, NOT the Security Domain's AID.
            ResponseAPDU aidResp = bibo.transmit(new CommandAPDU(0x00, 0x02, 0x00, 0x00, 256));
            assertEquals(0x9000, aidResp.getSW());
            assertArrayEquals(appletAIDBytes, aidResp.getData(),
                    "JCSystem.getAID() during processData() must return the target applet's AID");

            // INS 0x03: Read JCSystem.getPreviousContextAID() captured during processData()
            // GP 2.2.1 Section 7.3.3: the previous context must be the invoking Security Domain.
            ResponseAPDU prevAidResp = bibo.transmit(new CommandAPDU(0x00, 0x03, 0x00, 0x00, 256));
            assertEquals(0x9000, prevAidResp.getSW());
            assertArrayEquals(isdAIDBytes, prevAidResp.getData(),
                    "JCSystem.getPreviousContextAID() during processData() must return the ISD AID");
        }
    }

    // GP 2.2.1 Section 9.5.2.3.5: INSTALL [for personalization] shall only succeed if the
    // target application implements the Personalization or Application interface.
    // An applet that implements neither must be rejected.
    @Test
    public void testNonPersonalizableAppletRejected() throws Exception {
        JavaCardEngine sim = JavaCardEngine.create();

        AID appletAID = AIDUtil.create("0A0B0C0D0E0F101112");
        pro.javacard.capfile.AID jcaid = new pro.javacard.capfile.AID(AIDUtil.bytes(appletAID));

        // HelloWorldApplet is a plain Applet - does NOT implement Personalization or Application
        sim.loadApplet(appletAID, appletAID, HelloWorldApplet.class);

        try (EngineSession instance = sim.connect()) {
            APDUBIBO bibo = new APDUBIBO(instance);

            // Install the applet via GP
            PlaintextKeys pk = PlaintextKeys.defaultKey();
            GPSession gp = GPSession.discover(bibo);
            gp.openSecureChannel(pk, null, null, EnumSet.of(GPSession.APDUMode.ENC));
            gp.installAndMakeSelectable(jcaid, jcaid, jcaid,
                    EnumSet.noneOf(GPRegistryEntry.Privilege.class), new byte[4]);

            // Open new secure channel for personalization attempt
            PlaintextKeys pk2 = PlaintextKeys.defaultKey();
            gp = GPSession.discover(bibo);
            gp.openSecureChannel(pk2, null, null, EnumSet.of(GPSession.APDUMode.ENC));

            // Malformed INSTALL [for personalization] should be rejected with 6A80
            ResponseAPDU malformed = gp.transmit(new CommandAPDU(GPSession.CLA_GP, GPSession.INS_INSTALL, 0x20, 0x00, new byte[]{0x01}, 256));
            assertEquals(0x6A80, malformed.getSW());

            // INSTALL [for personalization] must fail - HelloWorldApplet doesn't implement
            // Personalization or Application interface
            GPSession finalGp = gp;
            GPException e = assertThrows(GPException.class, () -> finalGp.installForPersonalization(jcaid));
            assertEquals(0x6A80, e.sw);
        }
    }
}
