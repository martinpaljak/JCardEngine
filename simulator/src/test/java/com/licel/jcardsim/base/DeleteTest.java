// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2014 Robert Bachmann
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.samples.MultiInstanceApplet;
import com.licel.jcardsim.utils.AIDUtil;
import com.licel.jcardsim.utils.ByteUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class DeleteTest {
    private static final byte CLA = (byte) 0x80;
    private static final byte INS_GET_COUNT = 2;

    @Test
    public void testDeleteWorks() {
        AID aid1 = AIDUtil.create("d0000cafe00001");
        AID aid2 = AIDUtil.create("d0000cafe00002");

        Simulator simulator = new Simulator();

        // install first instance
        simulator.installApplet(aid1, MultiInstanceApplet.class);

        try (var bibo = simulator.connect()) {
            bibo.transmit(AIDUtil.select(aid1));

            // check instance counter == 1
            var result = bibo.transmit(new CommandAPDU(CLA, INS_GET_COUNT, 0, 0));
            assertEquals((short) result.getSW(), ISO7816.SW_NO_ERROR);
            assertEquals(ByteUtil.getShort(result.getData(), 0), 1);
        }

        // install second instance
        simulator.installApplet(aid2, MultiInstanceApplet.class);

        try (var bibo = simulator.connect()) {
            // check instance counter == 2
            bibo.transmit(AIDUtil.select(aid2));
            var result = bibo.transmit(new CommandAPDU(CLA, INS_GET_COUNT, 0, 0));
            assertEquals((short) result.getSW(), ISO7816.SW_NO_ERROR);
            assertEquals(ByteUtil.getShort(result.getData(), 0), 2);
        }

        // delete instance 1
        simulator.deleteApplet(aid1);

        try (var bibo = simulator.connect()) {
            // check instance counter == 1
            bibo.transmit(AIDUtil.select(aid2));
            var result = bibo.transmit(new CommandAPDU(CLA, INS_GET_COUNT, 0, 0));
            assertEquals((short) result.getSW(), ISO7816.SW_NO_ERROR);
            assertEquals(ByteUtil.getShort(result.getData(), 0), 1);
        }
    }
}
