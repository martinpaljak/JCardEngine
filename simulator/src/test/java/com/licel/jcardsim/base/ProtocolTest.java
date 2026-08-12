// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2014 Robert Bachmann
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.samples.DualInterfaceApplet;
import com.licel.jcardsim.utils.AIDUtil;
import com.licel.jcardsim.utils.ByteUtil;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class ProtocolTest {
    private static final byte CLA = (byte) 0x80;
    private static final byte INS_READ = 0;
    private static final byte INS_WRITE = 2;
    private static final byte INS_INFO = 4;

    private final AID aid = AIDUtil.create("D0000CAFE00001");


    @Test
    public void testDualInterfaceApplet() {
        final String expectedOutput = "CAFE9000".toLowerCase();

        Simulator simulator = new Simulator();
        simulator.installApplet(aid, DualInterfaceApplet.class);

        // check interface is T=0 (contacted)
        try (var conn = simulator.connect("*")) {
            var sel = conn.transmit(AIDUtil.select(aid));
            assertEquals((short) sel.getSW(), ISO7816.SW_NO_ERROR);

            var response = conn.transmit(new CommandAPDU(CLA, INS_INFO, 0, 0));
            assertEquals(response.getData()[0], APDU.PROTOCOL_T0);
            assertEquals((short) response.getSW(), ISO7816.SW_NO_ERROR);

            // store data
            response = conn.transmit(new CommandAPDU(CLA, INS_WRITE, 0, 0, new byte[]{(byte) 0xCA, (byte) 0xFE}));
            assertEquals((short) response.getSW(), ISO7816.SW_NO_ERROR);

            // read data
            response = conn.transmit(new CommandAPDU(CLA, INS_READ, 0, 0));
            assertEquals(ByteUtil.hex(response.getBytes()), expectedOutput);
        }

        // change protocol
        try (var conn = simulator.connect("T=CL")) {
            var response = conn.transmit(new CommandAPDU(CLA, INS_INFO, 0, 0));
            assertEquals(response.getData()[0], APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A | APDU.PROTOCOL_T1);
            assertEquals((short) response.getSW(), ISO7816.SW_NO_ERROR);

            // read data
            response = conn.transmit(new CommandAPDU(CLA, INS_READ, 0, 0));
            assertEquals(ByteUtil.hex(response.getBytes()), expectedOutput);

            // store data should fail
            response = conn.transmit(new CommandAPDU(CLA, INS_WRITE, 0, 0, new byte[]{(byte) 0xBA, (byte) 0xD0}));
            assertEquals((short) response.getSW(), ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Type B carries its own media nibble over the same T=1
        try (var conn = simulator.connect("T=CL,TYPE_B,T1")) {
            var response = conn.transmit(new CommandAPDU(CLA, INS_INFO, 0, 0));
            assertEquals(response.getData()[0], APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B | APDU.PROTOCOL_T1);
        }

        // connect() refuses an unusable protocol before taking the card lock
        assertThrows(IllegalArgumentException.class, () -> simulator.connect("T=42"));

        // After a contactless session, selecting on a contact session: select() must observe the
        // contact interface, not the previous contactless protocol. The applet rejects a SELECT
        // whose select()-time protocol differs from process()-time, so 9000 proves it matched.
        try (var conn = simulator.connect("*")) {
            assertEquals((short) conn.transmit(AIDUtil.select(aid)).getSW(), ISO7816.SW_NO_ERROR);
        }
    }
}
