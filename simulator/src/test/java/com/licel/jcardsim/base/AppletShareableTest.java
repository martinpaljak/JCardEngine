/*
 * Copyright 2022 Licel Corporation.
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

import com.licel.jcardsim.samples.GlobalArrayClientApplet;
import com.licel.jcardsim.samples.GlobalArrayServerApplet;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.JCSystem;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class AppletShareableTest {
    byte[] serverAppletAIDBytes = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    AID serverAppletAID;

    @Test
    public void testGetShareableApplet() {
        String shareableAppletAIDStr = "010203040506070809";
        AID shareableAppletAID = AIDUtil.create(shareableAppletAIDStr);

        Simulator instance = new Simulator();
        assertEquals(shareableAppletAID, instance.installApplet(shareableAppletAID, GlobalArrayServerApplet.class));
        assertTrue(instance.selectApplet(shareableAppletAID));
        instance._makeCurrent();
        assertNotNull(JCSystem.getAppletShareableInterfaceObject(shareableAppletAID, (byte) 0));
        instance._releaseCurrent();
    }

    @Test
    public void testGetNotShareableApplet() {
        String appletAIDStr = "090807060504030201";
        AID appletAID = AIDUtil.create(appletAIDStr);

        Simulator instance = new Simulator();
        assertEquals(appletAID, instance.installApplet(appletAID, GlobalArrayClientApplet.class, Hex.decode(appletAIDStr)));
        assertTrue(instance.selectApplet(appletAID));
        instance._makeCurrent();
        assertNull(JCSystem.getAppletShareableInterfaceObject(appletAID, (byte) 0));
        instance._releaseCurrent();
    }
}
