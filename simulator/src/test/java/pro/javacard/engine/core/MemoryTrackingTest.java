// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.core;

import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.testapplets.MemoryTestApplet;

import static org.junit.jupiter.api.Assertions.*;

public class MemoryTrackingTest {

    @Test
    @Disabled
    public void testArrayTracking() {
        Simulator simulator = new Simulator();
        AID appletAID = AIDUtil.create("010203040506070809");
        simulator.installApplet(appletAID, MemoryTestApplet.class);

        try (var bibo = simulator.connect()) {
            bibo.transmit(AIDUtil.select(appletAID));

            // Test boolean array allocation (INS 0x01)
            bibo.transmit(new CommandAPDU(0x00, 0x01, 0x00, 0x00));

            Object booleanArray = simulator.getBuffer("pro.javacard.engine.testapplets.MemoryTestApplet", 38); // line of 'booleanArray = ...'
            assertNotNull(booleanArray);
            if (booleanArray instanceof boolean[] fa) {
                assertEquals(10, fa.length);
            } else {
                fail("Expected boolean[] but got " + booleanArray.getClass().getName());
            }

            // Test short array allocation (INS 0x02)
            bibo.transmit(new CommandAPDU(0x00, 0x02, 0x00, 0x00));

            Object shortArray = simulator.getBuffer("pro.javacard.engine.testapplets.MemoryTestApplet", 42); // line of 'shortArray = ...'
            assertNotNull(shortArray);
            if (shortArray instanceof short[] sa) {
                assertEquals(5, sa.length);
            } else {
                fail("Expected short[] but got " + shortArray.getClass().getName());
            }

            // Test object array allocation (INS 0x03)
            bibo.transmit(new CommandAPDU(0x00, 0x03, 0x00, 0x00));

            Object objectArray = simulator.getBuffer("pro.javacard.engine.testapplets.MemoryTestApplet", 46); // line of 'objectArray = ...'
            assertNotNull(objectArray);
            if (objectArray instanceof Object[] oa) {
                assertEquals(3, oa.length);
            } else {
                fail("Expected Object[] but got " + objectArray.getClass().getName());
            }
        }
    }

    @Test
    public void testSensitiveArrays() {
        Simulator simulator = new Simulator();
        AID appletAID = AIDUtil.create("010203040506070809");
        simulator.installApplet(appletAID, MemoryTestApplet.class);

        try (var bibo = simulator.connect()) {
            bibo.transmit(AIDUtil.select(appletAID));

            // Test clearing (SensitiveArrays usage)
            bibo.transmit(new CommandAPDU(0x00, 0x04, 0x00, 0x00));

            // makeIntegritySensitiveArray results must pass assertIntegrity (SensitiveArrays, JC 3.2)
            assertEquals(0x9000, bibo.transmit(new CommandAPDU(0x00, 0x05, 0x00, 0x00)).getSW());
            assertEquals(0x9000, bibo.transmit(new CommandAPDU(0x00, 0x06, 0x00, 0x00)).getSW());
        }
    }
}
