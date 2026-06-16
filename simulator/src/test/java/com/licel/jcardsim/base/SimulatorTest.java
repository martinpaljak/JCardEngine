// SPDX-FileCopyrightText: 2013 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.samples.*;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import org.bouncycastle.util.encoders.Hex;
import org.testng.annotations.Test;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.engine.JavaCardEngineException;

import static org.testng.Assert.*;

public class SimulatorTest {
    private static final byte[] TEST_APPLET_AID_BYTES = Hex.decode("010203040506070809");
    private static final Class<? extends Applet> TEST_APPLET_CLASS = HelloWorldApplet.class;
    private static final AID TEST_APPLET_AID = new AID(TEST_APPLET_AID_BYTES, (short) 0, (byte) TEST_APPLET_AID_BYTES.length);

    byte[] createData = Hex.decode("0f0f");

    /**
     * Test of createApplet method, of class Simulator.
     */
    @Test
    public void testCreateApplet() {
        System.out.println("createApplet");
        Simulator instance = new Simulator();
        assertEquals(instance.installApplet(TEST_APPLET_AID, TEST_APPLET_CLASS, createData), TEST_APPLET_AID);
    }

    /**
     * Test of installApplet method, of class Simulator.
     */
    @Test
    public void testInstallApplet_AID_Class() {
        System.out.println("installApplet");
        Simulator instance = new Simulator();
        instance.installApplet(TEST_APPLET_AID, TEST_APPLET_CLASS);
        try (var bibo = instance.connect()) {
            assertEquals(bibo.transmit(AIDUtil.select(TEST_APPLET_AID)).getSW(), 0x9000);
        }
    }

    @Test
    public void testNopWithLengthExtensionsFails() {
        Simulator instance = new Simulator();
        instance.installApplet(TEST_APPLET_AID, TEST_APPLET_CLASS);
        try (var bibo = instance.connect()) {
            bibo.transmit(AIDUtil.select(TEST_APPLET_AID));
            // test NOP with Lc=1
            var response1 = bibo.transceive(new byte[]{0x01, 0x02, 0x00, 0x00, 0, 0, 1, 0xA});
            assertEquals(Util.getShort(response1, (short) 0), ISO7816.SW_WRONG_LENGTH);
            // test NOP with Le=1
            var response2 = bibo.transceive(new byte[]{0x01, 0x02, 0x00, 0x00, 0, 0, 1});
            assertEquals(Util.getShort(response2, (short) 0), ISO7816.SW_WRONG_LENGTH);
            // test NOP with Lc=1, Le=1
            var response3 = bibo.transceive(new byte[]{0x01, 0x02, 0x00, 0x00, 0, 0, 1, 0xA, 0, 1});
            assertEquals(Util.getShort(response3, (short) 0), ISO7816.SW_WRONG_LENGTH);
        }
    }

    /**
     * Test of transceive method, of class Simulator.
     */
    @Test
    public void testTransmitCommand() {
        Simulator instance = new Simulator();
        instance.installApplet(TEST_APPLET_AID, TEST_APPLET_CLASS);
        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(TEST_APPLET_AID));
            assertEquals(sel.getSW(), 0x9000);
            // test NOP
            var response = bibo.transmit(new CommandAPDU(0x01, 0x02, 0x00, 0x00));
            assertEquals(response.getSW(), 0x9000);
        }
    }

    /**
     * A reset-on-close session power-cycles the card.
     */
    @Test
    public void testReset() {
        Simulator instance = new Simulator();
        instance.installApplet(TEST_APPLET_AID, TEST_APPLET_CLASS);
        instance.connect("*", true).close();
        // installed applets survive a power cycle
        try (var bibo = instance.connect()) {
            assertEquals(bibo.transmit(AIDUtil.select(TEST_APPLET_AID)).getSW(), 0x9000);
        }
    }

    /**
     * Each simulator has an independent registry: an applet is selectable only where installed.
     */
    @Test
    public void testSelectAppletWith2Simulators() {
        System.out.println("selectAppletWith2Simulators");
        Simulator instance1 = new Simulator();
        Simulator instance2 = new Simulator();

        instance1.installApplet(TEST_APPLET_AID, TEST_APPLET_CLASS);
        // present only on instance1
        try (var bibo1 = instance1.connect(); var bibo2 = instance2.connect()) {
            assertEquals(bibo1.transmit(AIDUtil.select(TEST_APPLET_AID)).getSW(), 0x9000);
            assertEquals(bibo2.transmit(AIDUtil.select(TEST_APPLET_AID)).getSW(), 0x6A82);
        }

        instance2.installApplet(TEST_APPLET_AID, TEST_APPLET_CLASS);
        // now present on both
        try (var bibo1 = instance1.connect(); var bibo2 = instance2.connect()) {
            assertEquals(bibo1.transmit(AIDUtil.select(TEST_APPLET_AID)).getSW(), 0x9000);
            assertEquals(bibo2.transmit(AIDUtil.select(TEST_APPLET_AID)).getSW(), 0x9000);
        }

        instance2.deleteApplet(TEST_APPLET_AID);
        // deleted from instance2 only
        try (var bibo1 = instance1.connect(); var bibo2 = instance2.connect()) {
            assertEquals(bibo1.transmit(AIDUtil.select(TEST_APPLET_AID)).getSW(), 0x9000);
            assertEquals(bibo2.transmit(AIDUtil.select(TEST_APPLET_AID)).getSW(), 0x6A82);
        }

        instance1.deleteApplet(TEST_APPLET_AID);
        // gone from both
        try (var bibo1 = instance1.connect(); var bibo2 = instance2.connect()) {
            assertEquals(bibo1.transmit(AIDUtil.select(TEST_APPLET_AID)).getSW(), 0x6A82);
            assertEquals(bibo2.transmit(AIDUtil.select(TEST_APPLET_AID)).getSW(), 0x6A82);
        }
    }

    @Test
    public void testMagicField() {
        JavaCardEngine sim = JavaCardEngine.create();
        HelloWorldApplet.jcardengine = false; // other tests also load the same applet in exposed mode.
        assertFalse(HelloWorldApplet.jcardengine);
        sim.installApplet(TEST_APPLET_AID, TEST_APPLET_CLASS, new byte[0]);
        assertFalse(HelloWorldApplet.jcardengine);
        sim.deleteApplet(TEST_APPLET_AID);
        sim.installExposedApplet(TEST_APPLET_AID, TEST_APPLET_CLASS, new byte[0]);
        assertTrue(HelloWorldApplet.jcardengine);
    }

    @Test
    public void testAbortingCase() {
        final byte[] APPLET_AID_BYTES = Hex.decode("010203040506070809");
        final Class<? extends Applet> APPLET_CLASS = TestResponseDataAndStatusWordApplet.class;
        final byte CLA = (byte) 0x01;
        final byte INS = (byte) 0x02;

        Simulator instance = new Simulator();

        AID appletAID = AIDUtil.create(APPLET_AID_BYTES);
        instance.installApplet(appletAID, APPLET_CLASS);

        byte[] commandData = {0x12, 0x34, 0x56, 0x78};

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(appletAID));
            assertEquals(sel.getSW(), 0x9000);

            // Test for SW=0x61XX warning, must have response data
            var responseApdu = bibo.transmit(new CommandAPDU(CLA, INS, 0x61, 0x12, commandData, commandData.length));
            assertEquals(responseApdu.getData(), commandData);
            assertEquals((short) responseApdu.getSW(), (short) 0x6112);

            // Test for SW=0x64XX
            responseApdu = bibo.transmit(new CommandAPDU(CLA, INS, 0x64, 0x34, commandData, commandData.length));
            assertEquals(responseApdu.getData().length, 0);
            assertEquals((short) responseApdu.getSW(), (short) 0x6434);
        }

        // Try with base SimulatorRuntime
        instance = new Simulator();

        appletAID = AIDUtil.create(APPLET_AID_BYTES);
        instance.installApplet(appletAID, APPLET_CLASS);

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(appletAID));
            assertEquals(sel.getSW(), 0x9000);

            var responseApdu = bibo.transmit(new CommandAPDU(CLA, INS, 0x69, 0x85, commandData, commandData.length));
            assertEquals(responseApdu.getData().length, 0);
            assertEquals((short) responseApdu.getSW(), (short) 0x6985);
        }
    }

    @Test
    public void testManageChannelRejected() {
        Simulator instance = new Simulator();
        instance.installApplet(TEST_APPLET_AID, TEST_APPLET_CLASS);

        try (var bibo = instance.connect()) {
            // MANAGE CHANNEL OPEN (00 70 00 00) - rejected before applet is selected
            var response = bibo.transmit(new CommandAPDU(0x00, 0x70, 0x00, 0x00));
            assertEquals(response.getSW(), 0x6881);

            // Select applet, then try again - still rejected at JCRE level
            var sel = bibo.transmit(AIDUtil.select(TEST_APPLET_AID));
            assertEquals(sel.getSW(), 0x9000);

            // OPEN
            response = bibo.transmit(new CommandAPDU(0x00, 0x70, 0x00, 0x00));
            assertEquals(response.getSW(), 0x6881);

            // CLOSE (00 70 80 01)
            response = bibo.transmit(new CommandAPDU(0x00, 0x70, 0x80, 0x01));
            assertEquals(response.getSW(), 0x6881);

            // With channel bits in CLA (e.g. channel 1: CLA=0x01)
            response = bibo.transmit(new CommandAPDU(0x01, 0x70, 0x00, 0x00));
            assertEquals(response.getSW(), 0x6881);
        }
    }

    @Test
    public void testInstallAndRegisterMisbehaves() {
        var select = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, TEST_APPLET_AID_BYTES, 256);
        JavaCardEngine sim = JavaCardEngine.create();
        // Not installed yet
        assertThrows(IllegalArgumentException.class, () -> sim.deleteApplet(TEST_APPLET_AID));
        assertThrows(JavaCardEngineException.class, () -> sim.installApplet(TEST_APPLET_AID, AppletWithNoInstallMethod.class));
        sim.installApplet(TEST_APPLET_AID, AppletWithRegisterInProcess.class);
        try (var session = sim.connect()) {
            var result = session.transmit(select);
            assertEquals(result.getSW(), 0x6f00);
        }
        sim.deleteApplet(TEST_APPLET_AID);
        sim.installApplet(TEST_APPLET_AID, AppletThrowsInSelect.class);
        try (var session = sim.connect()) {
            var result = session.transmit(select);
            assertEquals(result.getSW(), 0x6999);
        }

        sim.deleteApplet(TEST_APPLET_AID);
        sim.installApplet(TEST_APPLET_AID, AppletThrowsInUninstall.class);
        try (var session = sim.connect()) {
            var result = session.transmit(select);
            assertEquals(result.getSW(), 0x9000);
            // random select - processed by the applet
            result = session.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, Hex.decode("01020304030201"), 256));
            assertEquals(result.getSW(), 0x9001);
        }
        assertThrows(JavaCardEngineException.class, () -> sim.deleteApplet(TEST_APPLET_AID));
    }
}
