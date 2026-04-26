// SPDX-FileCopyrightText: 2022 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
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
        try (var sim = instance.asCurrent()) {
            assertNotNull(JCSystem.getAppletShareableInterfaceObject(shareableAppletAID, (byte) 0));
        }
    }

    @Test
    public void testGetNotShareableApplet() {
        String appletAIDStr = "090807060504030201";
        AID appletAID = AIDUtil.create(appletAIDStr);

        Simulator instance = new Simulator();
        assertEquals(appletAID, instance.installApplet(appletAID, GlobalArrayClientApplet.class, Hex.decode(appletAIDStr)));
        assertTrue(instance.selectApplet(appletAID));
        try (var sim = instance.asCurrent()) {
            assertNull(JCSystem.getAppletShareableInterfaceObject(appletAID, (byte) 0));
        }
    }
}
