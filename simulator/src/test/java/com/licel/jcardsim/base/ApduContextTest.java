package com.licel.jcardsim.base;

import com.licel.jcardsim.samples.DummyApplet;
import com.licel.jcardsim.samples.HelloWorldApplet;
import com.licel.jcardsim.utils.AIDUtil;
import com.licel.jcardsim.utils.ByteUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.EngineSession;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ApduContextTest {

    @Test
    public void testCallingGetCurrentAPDUinWrongContextThrows() {
        Simulator simulator = new Simulator();
        AID otherAppletAID = AIDUtil.create("d0000cafe00001");
        AID dummyAppletAID = AIDUtil.create("d0000cafe00002");

        simulator.installExposedApplet(otherAppletAID, HelloWorldApplet.class);
        simulator.installExposedApplet(dummyAppletAID, DummyApplet.class);

        try (EngineSession session = simulator.connect()) {
            assertTrue(DummyApplet.exceptionInInstall);

            simulator.selectApplet(dummyAppletAID);
            assertTrue(DummyApplet.exceptionInSelect);

            byte[] response = session.transceive(new byte[]{(byte) 0x80, 0, 0, 0});
            assertEquals(ISO7816.SW_NO_ERROR, ByteUtil.getSW(response));
            assertTrue(DummyApplet.exceptionIllegalUse1);
            assertTrue(DummyApplet.exceptionIllegalUse2);

            simulator.selectApplet(otherAppletAID);
            assertTrue(DummyApplet.exceptionInDeselect);

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

        try (EngineSession session = simulator.connect()) {
            session.transceive(AIDUtil.select(otherAppletAID));
            session.transceive(AIDUtil.select(dummyAppletAID));
        }
    }
}
