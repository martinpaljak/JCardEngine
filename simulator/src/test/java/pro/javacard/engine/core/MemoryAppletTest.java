// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.core;

import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.testapplets.MemoryApplet;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class MemoryAppletTest {
    private static final String AID_HEX = "D23300000077" + "4D454D2D3031" + "01";

    private static BIBO selectFresh() {
        var sim = new Simulator();
        var aid = AIDUtil.create(AID_HEX);
        sim.installApplet(aid, MemoryApplet.class);
        var bibo = sim.connect();
        bibo.transmit(AIDUtil.select(aid));
        return bibo;
    }

    @Test
    void queryExtended() {
        try (var bibo = selectFresh()) {
            var r = bibo.transmit(new CommandAPDU(0x00, 0x42, 0x01, 0x00, 256));
            assertEquals(0x9000, r.getSW());
            r = bibo.transmit(new CommandAPDU(0x00, 0x42, 0x00, 0x00, 256));
            assertEquals(0x9000, r.getSW());
            var data = r.getData();
            assertEquals(12, data.length);

            var bb = ByteBuffer.wrap(data);
            var persistent = Integer.toUnsignedLong(bb.getInt());
            var reset = Integer.toUnsignedLong(bb.getInt());
            var deselect = Integer.toUnsignedLong(bb.getInt());
            assertTrue(persistent > 0);
            assertTrue(reset > 0);
            assertTrue(deselect > 0);
        }
    }

    @Test
    void queryLegacy() {
        try (var bibo = selectFresh()) {
            var r = bibo.transmit(new CommandAPDU(0x00, 0x42, 0x00, 0x01, 256));
            assertEquals(0x9000, r.getSW());
            var data = r.getData();
            assertEquals(6, data.length);

            var bb = ByteBuffer.wrap(data);
            var persistent = Short.toUnsignedInt(bb.getShort());
            var reset = Short.toUnsignedInt(bb.getShort());
            var deselect = Short.toUnsignedInt(bb.getShort());
            assertTrue(persistent > 0);
            assertTrue(reset > 0);
            assertTrue(deselect > 0);
        }
    }
}
