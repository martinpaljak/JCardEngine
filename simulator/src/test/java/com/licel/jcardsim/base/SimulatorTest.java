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
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.engine.JavaCardEngineException;

import static org.junit.jupiter.api.Assertions.*;

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
        assertEquals(TEST_APPLET_AID, instance.installApplet(TEST_APPLET_AID, TEST_APPLET_CLASS, createData));
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
            assertEquals(0x9000, bibo.transmit(AIDUtil.select(TEST_APPLET_AID)).getSW());
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
            assertEquals(ISO7816.SW_WRONG_LENGTH, Util.getShort(response1, (short) 0));
            // test NOP with Le=1
            var response2 = bibo.transceive(new byte[]{0x01, 0x02, 0x00, 0x00, 0, 0, 1});
            assertEquals(ISO7816.SW_WRONG_LENGTH, Util.getShort(response2, (short) 0));
            // test NOP with Lc=1, Le=1
            var response3 = bibo.transceive(new byte[]{0x01, 0x02, 0x00, 0x00, 0, 0, 1, 0xA, 0, 1});
            assertEquals(ISO7816.SW_WRONG_LENGTH, Util.getShort(response3, (short) 0));
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
            assertEquals(0x9000, sel.getSW());
            // test NOP
            var response = bibo.transmit(new CommandAPDU(0x01, 0x02, 0x00, 0x00));
            assertEquals(0x9000, response.getSW());
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
            assertEquals(0x9000, bibo.transmit(AIDUtil.select(TEST_APPLET_AID)).getSW());
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
            assertEquals(0x9000, bibo1.transmit(AIDUtil.select(TEST_APPLET_AID)).getSW());
            assertEquals(0x6A82, bibo2.transmit(AIDUtil.select(TEST_APPLET_AID)).getSW());
        }

        instance2.installApplet(TEST_APPLET_AID, TEST_APPLET_CLASS);
        // now present on both
        try (var bibo1 = instance1.connect(); var bibo2 = instance2.connect()) {
            assertEquals(0x9000, bibo1.transmit(AIDUtil.select(TEST_APPLET_AID)).getSW());
            assertEquals(0x9000, bibo2.transmit(AIDUtil.select(TEST_APPLET_AID)).getSW());
        }

        instance2.deleteApplet(TEST_APPLET_AID);
        // deleted from instance2 only
        try (var bibo1 = instance1.connect(); var bibo2 = instance2.connect()) {
            assertEquals(0x9000, bibo1.transmit(AIDUtil.select(TEST_APPLET_AID)).getSW());
            assertEquals(0x6A82, bibo2.transmit(AIDUtil.select(TEST_APPLET_AID)).getSW());
        }

        instance1.deleteApplet(TEST_APPLET_AID);
        // gone from both
        try (var bibo1 = instance1.connect(); var bibo2 = instance2.connect()) {
            assertEquals(0x6A82, bibo1.transmit(AIDUtil.select(TEST_APPLET_AID)).getSW());
            assertEquals(0x6A82, bibo2.transmit(AIDUtil.select(TEST_APPLET_AID)).getSW());
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
            assertEquals(0x9000, sel.getSW());

            // Test for SW=0x61XX warning, must have response data
            var responseApdu = bibo.transmit(new CommandAPDU(CLA, INS, 0x61, 0x12, commandData, commandData.length));
            assertArrayEquals(commandData, responseApdu.getData());
            assertEquals(0x6112, (short) responseApdu.getSW());

            // Test for SW=0x64XX
            responseApdu = bibo.transmit(new CommandAPDU(CLA, INS, 0x64, 0x34, commandData, commandData.length));
            assertEquals(0, responseApdu.getData().length);
            assertEquals(0x6434, (short) responseApdu.getSW());
        }

        // Try with base SimulatorRuntime
        instance = new Simulator();

        appletAID = AIDUtil.create(APPLET_AID_BYTES);
        instance.installApplet(appletAID, APPLET_CLASS);

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(appletAID));
            assertEquals(0x9000, sel.getSW());

            var responseApdu = bibo.transmit(new CommandAPDU(CLA, INS, 0x69, 0x85, commandData, commandData.length));
            assertEquals(0, responseApdu.getData().length);
            assertEquals(0x6985, (short) responseApdu.getSW());
        }
    }

    @Test
    public void testManageChannelRejected() {
        Simulator instance = new Simulator();
        instance.installApplet(TEST_APPLET_AID, TEST_APPLET_CLASS);

        try (var bibo = instance.connect()) {
            // MANAGE CHANNEL OPEN (00 70 00 00) - rejected before applet is selected
            var response = bibo.transmit(new CommandAPDU(0x00, 0x70, 0x00, 0x00));
            assertEquals(0x6881, response.getSW());

            // Select applet, then try again - still rejected at JCRE level
            var sel = bibo.transmit(AIDUtil.select(TEST_APPLET_AID));
            assertEquals(0x9000, sel.getSW());

            // OPEN
            response = bibo.transmit(new CommandAPDU(0x00, 0x70, 0x00, 0x00));
            assertEquals(0x6881, response.getSW());

            // CLOSE (00 70 80 01)
            response = bibo.transmit(new CommandAPDU(0x00, 0x70, 0x80, 0x01));
            assertEquals(0x6881, response.getSW());

            // With channel bits in CLA (e.g. channel 1: CLA=0x01)
            response = bibo.transmit(new CommandAPDU(0x01, 0x70, 0x00, 0x00));
            assertEquals(0x6881, response.getSW());
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
            assertEquals(0x6f00, result.getSW());
        }
        sim.deleteApplet(TEST_APPLET_AID);
        sim.installApplet(TEST_APPLET_AID, AppletThrowsInSelect.class);
        try (var session = sim.connect()) {
            var result = session.transmit(select);
            assertEquals(0x6999, result.getSW());
        }

        sim.deleteApplet(TEST_APPLET_AID);
        sim.installApplet(TEST_APPLET_AID, AppletThrowsInUninstall.class);
        try (var session = sim.connect()) {
            var result = session.transmit(select);
            assertEquals(0x9000, result.getSW());
            // random select - processed by the applet
            result = session.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, Hex.decode("01020304030201"), 256));
            assertEquals(0x9001, result.getSW());
        }
        assertThrows(JavaCardEngineException.class, () -> sim.deleteApplet(TEST_APPLET_AID));
    }
}
