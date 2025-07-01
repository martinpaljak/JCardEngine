package com.licel.jcardsim.base;

import com.licel.jcardsim.samples.DualInterfaceApplet;
import com.licel.jcardsim.utils.AIDUtil;
import com.licel.jcardsim.utils.ByteUtil;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.core.EngineSession;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ProtocolTest {
    private static final byte CLA = (byte) 0x80;
    private static final byte INS_READ = 0;
    private static final byte INS_WRITE = 2;
    private static final byte INS_INFO = 4;

    private final AID aid = AIDUtil.create("D0000CAFE00001");


    @Test
    public void testDualInterfaceApplet() {
        final String expectedOutput = "CAFE9000";
        byte[] response;

        Simulator simulator = new Simulator();
        simulator.installApplet(aid, DualInterfaceApplet.class);
        simulator.selectApplet(aid);

        // check interface is T=0 (contacted)
        try (EngineSession conn = simulator.connect("*")) {
            response = conn.transmitCommand(new byte[]{CLA, INS_INFO, 0, 0});
            assertEquals(APDU.PROTOCOL_T0, response[0]);
            assertEquals(ISO7816.SW_NO_ERROR, ByteUtil.getSW(response));

            // store data
            response = conn.transmitCommand(new byte[]{CLA, INS_WRITE, 0, 0, 2, (byte) 0xCA, (byte) 0xFE});
            assertEquals(ISO7816.SW_NO_ERROR, ByteUtil.getSW(response));

            // read data
            response = conn.transmitCommand(new byte[]{CLA, INS_READ, 0, 0});
            assertEquals(expectedOutput, ByteUtil.hexString(response));
        }

        // change protocol
        try (EngineSession conn = simulator.connect("T=CL")) {
            response = conn.transmitCommand(new byte[]{CLA, INS_INFO, 0, 0});
            assertEquals(APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A | APDU.PROTOCOL_T1, response[0]);
            assertEquals(ISO7816.SW_NO_ERROR, ByteUtil.getSW(response));

            // read data
            response = conn.transmitCommand(new byte[]{CLA, INS_READ, 0, 0});
            assertEquals(expectedOutput, ByteUtil.hexString(response));

            // store data should fail
            response = conn.transmitCommand(new byte[]{CLA, INS_WRITE, 0, 0, 2, (byte) 0xBA, (byte) 0xD0});
            assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, ByteUtil.getSW(response));
        }
    }
}
