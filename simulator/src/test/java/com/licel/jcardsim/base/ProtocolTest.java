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
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
            assertEquals(ISO7816.SW_NO_ERROR, (short) sel.getSW());

            var response = conn.transmit(new CommandAPDU(CLA, INS_INFO, 0, 0));
            assertEquals(APDU.PROTOCOL_T0, response.getData()[0]);
            assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());

            // store data
            response = conn.transmit(new CommandAPDU(CLA, INS_WRITE, 0, 0, new byte[]{(byte) 0xCA, (byte) 0xFE}));
            assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());

            // read data
            response = conn.transmit(new CommandAPDU(CLA, INS_READ, 0, 0));
            assertEquals(expectedOutput, ByteUtil.hex(response.getBytes()));
        }

        // change protocol
        try (var conn = simulator.connect("T=CL")) {
            var response = conn.transmit(new CommandAPDU(CLA, INS_INFO, 0, 0));
            assertEquals(APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A | APDU.PROTOCOL_T1, response.getData()[0]);
            assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());

            // read data
            response = conn.transmit(new CommandAPDU(CLA, INS_READ, 0, 0));
            assertEquals(expectedOutput, ByteUtil.hex(response.getBytes()));

            // store data should fail
            response = conn.transmit(new CommandAPDU(CLA, INS_WRITE, 0, 0, new byte[]{(byte) 0xBA, (byte) 0xD0}));
            assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, (short) response.getSW());
        }
    }
}
