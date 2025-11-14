package com.licel.jcardsim.base;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import com.licel.jcardsim.utils.AIDUtil;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.testapplets.FaultApplet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class FaultTest {
    @Test
    public void testFault() {
        Simulator instance = new Simulator();
        // Flip condition
        instance.faultyAt(FaultApplet.class, 54);
        var aid = AIDUtil.create("010203040506");
        assertTrue(instance.installApplet(aid, FaultApplet.class).equals(aid));

        assertTrue(instance.selectApplet(aid));

        var res = instance.transmitCommand(new CommandAPDU(0x00, 0x02, 0x00, 0x00).getBytes());
        assertEquals(0x9000, new ResponseAPDU(res).getSW());
    }

    @Test
    public void testNoFault() {
        Simulator instance = new Simulator();
        var aid = AIDUtil.create("010203040506");
        assertTrue(instance.installApplet(aid, FaultApplet.class).equals(aid));

        assertTrue(instance.selectApplet(aid));

        var res = instance.transmitCommand(new CommandAPDU(0x00, 0x02, 0x00, 0x00).getBytes());
        assertEquals(0x6f00, new ResponseAPDU(res).getSW());
    }
}
