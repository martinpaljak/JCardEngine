/*
 * Copyright 2025 Martin Paljak <martin@martinpaljak.net>
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
package pro.javacard.engine.core;

import org.junit.jupiter.api.Disabled;
import pro.javacard.engine.testapplets.MemoryTestApplet;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class MemoryTrackingTest {

    @Test
    @Disabled
    public void testArrayTracking() {
        Simulator simulator = new Simulator();
        AID appletAID = AIDUtil.create("010203040506070809");
        simulator.installApplet(appletAID, MemoryTestApplet.class);
        simulator.selectApplet(appletAID);

        // Test boolean array allocation (INS 0x01)
        simulator.transceive(new byte[]{0x00, 0x01, 0x00, 0x00});

        Object booleanArray = simulator.getBuffer("pro.javacard.engine.testapplets.MemoryTestApplet", 38); // line of 'booleanArray = ...'
        assertNotNull(booleanArray, "Boolean array should be tracked");
        if (booleanArray instanceof boolean[] fa) {
            assertEquals(10, fa.length);
        } else {
            fail("Expected boolean[] but got " + booleanArray.getClass().getName());
        }

        // Test short array allocation (INS 0x02)
        simulator.transceive(new byte[]{0x00, 0x02, 0x00, 0x00});
        
        Object shortArray = simulator.getBuffer("pro.javacard.engine.testapplets.MemoryTestApplet", 42); // line of 'shortArray = ...'
        assertNotNull(shortArray, "Short array should be tracked");
        if (shortArray instanceof short[] sa) {
            assertEquals(5, sa.length);
        } else {
            fail("Expected short[] but got " + shortArray.getClass().getName());
        }

        // Test object array allocation (INS 0x03)
        simulator.transceive(new byte[]{0x00, 0x03, 0x00, 0x00});
        
        Object objectArray = simulator.getBuffer("pro.javacard.engine.testapplets.MemoryTestApplet", 46); // line of 'objectArray = ...'
        assertNotNull(objectArray, "Object array should be tracked");
        if (objectArray instanceof Object[] oa) {
            assertEquals(3, oa.length);
        } else {
            fail("Expected Object[] but got " + objectArray.getClass().getName());
        }
    }

    @Test
    public void testSensitiveArrays() {
        Simulator simulator = new Simulator();
        AID appletAID = AIDUtil.create("010203040506070809");
        simulator.installApplet(appletAID, MemoryTestApplet.class);
        simulator.selectApplet(appletAID);

        // Test clearing (SensitiveArrays usage)
        simulator.transceive(new byte[]{0x00, 0x04, 0x00, 0x00});

        // Test makeIntegritySensitiveArray (transient)
        simulator.transceive(new byte[]{0x00, 0x05, 0x00, 0x00});

        // Test makeIntegritySensitiveArray (persistent)
        simulator.transceive(new byte[]{0x00, 0x06, 0x00, 0x00});
    }
}
