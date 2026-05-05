// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.utils.AIDUtil;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.faulty.FaultyConfig;
import pro.javacard.engine.testapplets.FaultApplet;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class FaultTest {
    @Test
    public void testFault() {
        // Flip condition on step 2 (SELECT is step 1, the test command is step 2)
        var config = FaultyConfig.builder()
                .faultyAt(2, FaultApplet.class, 64)
                .faultyAt(2, FaultApplet.class, 26)

                .build();
        var instance = new Simulator(config);
        var aid = AIDUtil.create("010203040506");
        assertEquals(instance.installApplet(aid, FaultApplet.class), aid);

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(aid));
            assertEquals(0x9000, sel.getSW());

            var res = bibo.transmit(new CommandAPDU(0x00, 0x02, 0x00, 0x00));
            assertEquals(0x9000, res.getSW());
        }
    }

    @Test
    public void testNoFault() {
        var instance = new Simulator();
        var aid = AIDUtil.create("010203040506");
        assertEquals(instance.installApplet(aid, FaultApplet.class), aid);

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(aid));
            assertEquals(0x9000, sel.getSW());

            var res = bibo.transmit(new CommandAPDU(0x00, 0x02, 0x00, 0x00));
            assertEquals(0x6f00, res.getSW());
        }
    }
}
