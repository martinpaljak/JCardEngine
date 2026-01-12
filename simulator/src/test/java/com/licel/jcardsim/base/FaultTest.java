package com.licel.jcardsim.base;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import com.licel.jcardsim.utils.AIDUtil;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.faulty.FaultyConfig;
import pro.javacard.engine.testapplets.FaultApplet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class FaultTest {
    @Test
    public void testFault() {
        // Flip condition on step 2 (SELECT is step 1, the test command is step 2)
        var config = FaultyConfig.builder()
                .faultyAt(2, FaultApplet.class, 62)
                .faultyAt(2, FaultApplet.class, 24)

                .build();
        var instance = new Simulator(config);
        var aid = AIDUtil.create("010203040506");
        assertEquals(instance.installApplet(aid, FaultApplet.class), aid);

        assertTrue(instance.selectApplet(aid));

        var res = instance.transmitCommand(new CommandAPDU(0x00, 0x02, 0x00, 0x00).getBytes());
        assertEquals(0x9000, new ResponseAPDU(res).getSW());
    }

    @Test
    public void testNoFault() {
        var instance = new Simulator();
        var aid = AIDUtil.create("010203040506");
        assertEquals(instance.installApplet(aid, FaultApplet.class), aid);

        assertTrue(instance.selectApplet(aid));

        var res = instance.transmitCommand(new CommandAPDU(0x00, 0x02, 0x00, 0x00).getBytes());
        assertEquals(0x6f00, new ResponseAPDU(res).getSW());
    }
}
