/*
 * Copyright 2013 Licel LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.licel.jcardsim.base;

import com.licel.jcardsim.samples.HelloWorldApplet;
import com.licel.jcardsim.samples.TestResponseDataAndStatusWordApplet;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;

import javax.smartcardio.ResponseAPDU;

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
        assertTrue(instance.selectApplet(TEST_APPLET_AID));
    }

    @Test
    public void testNopWithLengthExtensionsFails() {
        Simulator instance = new Simulator();
        instance.installApplet(TEST_APPLET_AID, TEST_APPLET_CLASS);
        instance.selectApplet(TEST_APPLET_AID);
        // test NOP with Lc=1
        byte[] response1 = instance.transmitCommand(new byte[]{0x01, 0x02, 0x00, 0x00, 0, 0, 1, 0xA});
        assertEquals(ISO7816.SW_WRONG_LENGTH, Util.getShort(response1, (short) 0));
        // test NOP with Le=1
        byte[] response2 = instance.transmitCommand(new byte[]{0x01, 0x02, 0x00, 0x00, 0, 0, 1});
        assertEquals(ISO7816.SW_WRONG_LENGTH, Util.getShort(response2, (short) 0));
        // test NOP with Lc=1, Le=1
        byte[] response3 = instance.transmitCommand(new byte[]{0x01, 0x02, 0x00, 0x00, 0, 0, 1, 0xA, 0, 1});
        assertEquals(ISO7816.SW_WRONG_LENGTH, Util.getShort(response3, (short) 0));
    }

    /**
     * Test of selectApplet method, of class Simulator.
     */
    @Test
    public void testSelectApplet() {
        Simulator instance = new Simulator();
        instance.installApplet(TEST_APPLET_AID, TEST_APPLET_CLASS);
        assertTrue(instance.selectApplet(TEST_APPLET_AID));
    }

    /**
     * Test of selectAppletWithResult method, of class Simulator.
     */
    @Test
    public void testSelectAppletWithResult() {
        Simulator instance = new Simulator();
        instance.installApplet(TEST_APPLET_AID, TEST_APPLET_CLASS);
        byte[] result = instance.selectAppletWithResult(TEST_APPLET_AID);
        assertEquals((byte) 0x90, result[0]);
        assertEquals(0x00, result[1]);
    }

    /**
     * Test of transmitCommand method, of class Simulator.
     */
    @Test
    public void testTransmitCommand() {
        Simulator instance = new Simulator();
        instance.installApplet(TEST_APPLET_AID, TEST_APPLET_CLASS);
        assertTrue(instance.selectApplet(TEST_APPLET_AID));
        // test NOP
        byte[] response = instance.transmitCommand(new byte[]{0x01, 0x02, 0x00, 0x00});
        assertArrayEquals(new byte[]{(byte) 0x90, 0x00}, response);
    }

    /**
     * Test of reset method, of class Simulator.
     */
    @Test
    public void testReset() {
        Simulator instance = new Simulator();
        instance.installApplet(TEST_APPLET_AID, TEST_APPLET_CLASS);
        instance.reset();
        // after reset installed applets not deleted
        assertTrue(instance.selectApplet(TEST_APPLET_AID));
    }

    /**
     * Test of selectApplet method, of class Simulator.
     */
    @Test
    public void testSelectAppletWith2Simulators() {
        System.out.println("selectAppletWith2Simulators");
        Simulator instance1 = new Simulator();
        Simulator instance2 = new Simulator();

        instance1.installApplet(TEST_APPLET_AID, TEST_APPLET_CLASS);
        assertTrue(instance1.selectApplet(TEST_APPLET_AID));
        assertFalse(instance2.selectApplet(TEST_APPLET_AID));

        instance2.installApplet(TEST_APPLET_AID, TEST_APPLET_CLASS);
        assertTrue(instance1.selectApplet(TEST_APPLET_AID));
        assertTrue(instance2.selectApplet(TEST_APPLET_AID));

        instance2.deleteApplet(TEST_APPLET_AID);
        assertTrue(instance1.selectApplet(TEST_APPLET_AID));
        assertFalse(instance2.selectApplet(TEST_APPLET_AID));

        instance1.deleteApplet(TEST_APPLET_AID);
        assertFalse(instance1.selectApplet(TEST_APPLET_AID));
        assertFalse(instance2.selectApplet(TEST_APPLET_AID));
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
        assertTrue(instance.selectApplet(appletAID));

        byte[] commandData = {0x12, 0x34, 0x56, 0x78};
        byte[] apduHeader = new byte[]{CLA, INS, 0x69, (byte) 0x85};

        byte[] apduForTransmit = new byte[apduHeader.length + 1 + commandData.length + 1];
        System.arraycopy(apduHeader, 0, apduForTransmit, 0, apduHeader.length);
        apduForTransmit[apduHeader.length] = (byte) commandData.length;
        System.arraycopy(commandData, 0, apduForTransmit, apduHeader.length + 1, commandData.length);
        apduForTransmit[apduHeader.length + 1 + commandData.length] = (byte) commandData.length;

        // Test for SW=0x61XX warning, must have response data
        apduHeader = new byte[]{CLA, INS, 0x61, 0x12};

        apduForTransmit = new byte[apduHeader.length + 1 + commandData.length + 1];
        System.arraycopy(apduHeader, 0, apduForTransmit, 0, apduHeader.length);
        apduForTransmit[apduHeader.length] = (byte) commandData.length;
        System.arraycopy(commandData, 0, apduForTransmit, apduHeader.length + 1, commandData.length);
        apduForTransmit[apduHeader.length + 1 + commandData.length] = (byte) commandData.length;

        byte[] response = instance.transmitCommand(apduForTransmit);

        ResponseAPDU responseApdu = new ResponseAPDU(response);
        assertArrayEquals(commandData, responseApdu.getData());
        assertEquals(0x6112, (short) responseApdu.getSW());

        // Test for SW=0x64XX
        apduHeader = new byte[]{CLA, INS, 0x64, 0x34};

        apduForTransmit = new byte[apduHeader.length + 1 + commandData.length + 1];
        System.arraycopy(apduHeader, 0, apduForTransmit, 0, apduHeader.length);
        apduForTransmit[apduHeader.length] = (byte) commandData.length;
        System.arraycopy(commandData, 0, apduForTransmit, apduHeader.length + 1, commandData.length);
        apduForTransmit[apduHeader.length + 1 + commandData.length] = (byte) commandData.length;

        response = instance.transmitCommand(apduForTransmit);

        responseApdu = new ResponseAPDU(response);
        assertEquals(0, responseApdu.getData().length);
        assertEquals(0x6434, (short) responseApdu.getSW());

        // Try with base SimulatorRuntime
        instance = new Simulator();

        appletAID = AIDUtil.create(APPLET_AID_BYTES);
        instance.installApplet(appletAID, APPLET_CLASS);
        assertTrue(instance.selectApplet(appletAID));

        apduHeader = new byte[]{CLA, INS, 0x69, (byte) 0x85};
        apduForTransmit = new byte[apduHeader.length + 1 + commandData.length + 1];
        System.arraycopy(apduHeader, 0, apduForTransmit, 0, apduHeader.length);
        apduForTransmit[apduHeader.length] = (byte) commandData.length;
        System.arraycopy(commandData, 0, apduForTransmit, apduHeader.length + 1, commandData.length);
        apduForTransmit[apduHeader.length + 1 + commandData.length] = (byte) commandData.length;

        response = instance.transmitCommand(apduForTransmit);

        responseApdu = new ResponseAPDU(response);
        assertEquals(0, responseApdu.getData().length);
        assertEquals(0x6985, (short) responseApdu.getSW());
    }
}
