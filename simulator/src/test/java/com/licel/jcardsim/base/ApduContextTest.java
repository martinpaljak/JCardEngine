// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2014 Robert Bachmann
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.samples.DummyApplet;
import com.licel.jcardsim.samples.HelloWorldApplet;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class ApduContextTest {

    @Test
    public void testCallingGetCurrentAPDUinWrongContextThrows() {
        Simulator simulator = new Simulator();
        AID otherAppletAID = AIDUtil.create("d0000cafe00001");
        AID dummyAppletAID = AIDUtil.create("d0000cafe00002");

        simulator.installExposedApplet(otherAppletAID, HelloWorldApplet.class);
        simulator.installExposedApplet(dummyAppletAID, DummyApplet.class);

        try (var bibo = simulator.connect()) {
            assertTrue(DummyApplet.exceptionInInstall);

            bibo.transmit(AIDUtil.select(dummyAppletAID));
            assertTrue(DummyApplet.exceptionInSelect);

            var response = bibo.transmit(new CommandAPDU(0x80, 0, 0, 0));
            assertEquals((short) response.getSW(), ISO7816.SW_NO_ERROR);
            assertTrue(DummyApplet.exceptionIllegalUse1);
            assertTrue(DummyApplet.exceptionIllegalUse2);

            bibo.transmit(AIDUtil.select(otherAppletAID));
            assertTrue(DummyApplet.exceptionInDeselect);
            // JCRE 3.2 3.4: selectingApplet() is false during deselect(), even though the SELECT that
            // triggers it goes on to select another applet
            assertFalse(DummyApplet.selectingInDeselect);

            simulator.deleteApplet(dummyAppletAID);
            assertTrue(DummyApplet.exceptionInUninstall);
        }
    }

    @Test
    public void testDeselectViaSelect() {
        Simulator simulator = new Simulator();
        AID otherAppletAID = AIDUtil.create("d0000cafe00001");
        AID dummyAppletAID = AIDUtil.create("d0000cafe00002");

        simulator.installApplet(otherAppletAID, DummyApplet.class);
        simulator.installApplet(dummyAppletAID, DummyApplet.class);

        try (var bibo = simulator.connect()) {
            bibo.transmit(AIDUtil.select(otherAppletAID));
            bibo.transmit(AIDUtil.select(dummyAppletAID));
        }
    }
}
