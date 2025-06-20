package com.licel.jcardsim.base;

import com.licel.jcardsim.samples.MultiInstanceApplet;
import com.licel.jcardsim.utils.AIDUtil;
import com.licel.jcardsim.utils.ByteUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

// FIXME: this test makes sense, and works via intellij, but fails under maven
// Probably has something to do with the removal of the threadlocal simulator hackery
// re-visit once that seems done. As the applet instance counter is static, we can't "unload"
// the class easily, and the counter value remains.
public class DeleteTest {
    private static final byte CLA = (byte) 0x80;
    private static final byte INS_GET_COUNT = 2;

    // FIXME: Ignored
    public void testDeleteWorks() {
        byte[] result;
        AID aid1 = AIDUtil.create("d0000cafe00001");
        AID aid2 = AIDUtil.create("d0000cafe00002");

        Simulator simulator = new Simulator();

        // install first instance
        simulator.installApplet(aid1, MultiInstanceApplet.class);
        simulator.selectApplet(aid1);

        // check instance counter == 1
        result = simulator.transmitCommand(new byte[]{CLA, INS_GET_COUNT, 0, 0});
        assertEquals(1, ByteUtil.getShort(result, 0));
        assertEquals(ISO7816.SW_NO_ERROR, ByteUtil.getSW(result));

        // install second instance
        simulator.installApplet(aid2, MultiInstanceApplet.class);

        // check instance counter == 2
        result = simulator.transmitCommand(new byte[]{CLA, INS_GET_COUNT, 0, 0});
        assertEquals(2, ByteUtil.getShort(result, 0));
        assertEquals(ISO7816.SW_NO_ERROR, ByteUtil.getSW(result));

        // delete instance 1
        simulator.deleteApplet(aid1);

        // check instance counter == 1
        simulator.selectApplet(aid2);
        result = simulator.transmitCommand(new byte[]{CLA, INS_GET_COUNT, 0, 0});
        assertEquals(1, ByteUtil.getShort(result, 0));
        assertEquals(ISO7816.SW_NO_ERROR, ByteUtil.getSW(result));
    }
}
