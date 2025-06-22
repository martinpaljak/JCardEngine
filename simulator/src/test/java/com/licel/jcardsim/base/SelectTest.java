package com.licel.jcardsim.base;

import com.licel.jcardsim.samples.MultiInstanceApplet;
import com.licel.jcardsim.utils.AIDUtil;
import com.licel.jcardsim.utils.ByteUtil;
import javacard.framework.*;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class SelectTest {
    private static final byte CLA = (byte) 0x80;
    private static final byte INS_GET_FULL_AID = 0;


    public static class UnselectableApplet extends Applet {
        public static boolean selectedCalled;

        private byte[] array = new byte[12];

        @SuppressWarnings("unused")
        public static void install(byte[] bArray, short bOffset, byte bLength) {
            new UnselectableApplet().register();
        }

        @Override
        public boolean select() {
            selectedCalled = true;
            return false;
        }

        @Override
        public void process(APDU apdu) throws ISOException {
        }

        public boolean selectCalled() {
            return selectedCalled;
        }
    }


    @Test
    public void testAidComparator() {
        AID[] input = new AID[]{
                AIDUtil.create("A000008812"),
                AIDUtil.create("FF00066767"),
                AIDUtil.create("D0000CAFE001"),
                AIDUtil.create("D0000CAFE000"),
                AIDUtil.create("D0000CAFE00023"),
                AIDUtil.create("D0000CAFE00001"),
                AIDUtil.create("0100CAFE01"),
                AIDUtil.create("0200888888")
        };

        AID[] expected = new AID[]{
                AIDUtil.create("0100CAFE01"),
                AIDUtil.create("0200888888"),
                AIDUtil.create("A000008812"),
                AIDUtil.create("D0000CAFE000"),
                AIDUtil.create("D0000CAFE00001"),
                AIDUtil.create("D0000CAFE00023"),
                AIDUtil.create("D0000CAFE001"),
                AIDUtil.create("FF00066767")
        };
        Arrays.sort(input, AIDUtil.comparator());

        assertArrayEquals(expected, input);
    }

    private Simulator prepareSimulator() {
        AID aid0 = AIDUtil.create("010203040506070809");
        AID aid1 = AIDUtil.create("d0000cafe00001");
        AID aid2 = AIDUtil.create("d0000cafe00002");

        Simulator simulator = new Simulator();
        simulator.installApplet(aid0, MultiInstanceApplet.class);
        simulator.installApplet(aid2, MultiInstanceApplet.class);
        simulator.installApplet(aid1, MultiInstanceApplet.class);
        return simulator;
    }

    @Test
    public void testPartialSelectWorks1() {
        Simulator simulator = prepareSimulator();

        // should select d0000cafe00001
        assertTrue(simulator.selectApplet(AIDUtil.create("d0000cafe0")));
        byte[] expected = Hex.decode("d0000cafe000019000");
        byte[] actual = simulator.transmitCommand(new byte[]{CLA, INS_GET_FULL_AID, 0, 0});
        assertEquals(Arrays.toString(expected), Arrays.toString(actual));
    }

    @Test
    public void testPartialSelectWorks2() {
        Simulator simulator = prepareSimulator();

        // should select d0000cafe00001
        simulator.transmitCommand(new byte[]{0, ISO7816.INS_SELECT, 4, 0, 1, (byte) 0xD0});

        byte[] expected = Hex.decode("d0000cafe000019000");
        byte[] actual = simulator.transmitCommand(new byte[]{CLA, INS_GET_FULL_AID, 0, 0});
        assertEquals(Arrays.toString(expected), Arrays.toString(actual));
    }

    @Test
    public void testEmptySelectWorks() {
        // Expected to always reset the currentAID and return "not found"
        Simulator simulator = prepareSimulator();
        byte[] actual = simulator.transmitCommand(new byte[]{0, ISO7816.INS_SELECT, 4, 0});
        assertEquals(Arrays.toString(Hex.decode("6A82")), Arrays.toString(actual));
    }

    @Test
    public void testCanNotSelectUnselectableApplet() {
        AID aid = AIDUtil.create("010203040506070809");
        Simulator simulator = new Simulator();
        simulator.installExposedApplet(aid, UnselectableApplet.class);

        byte[] result = simulator.selectAppletWithResult(aid);
        assertEquals(2, result.length);
        assertEquals(ISO7816.SW_APPLET_SELECT_FAILED, Util.getShort(result, (short) 0));
        assertTrue(UnselectableApplet.selectedCalled);
    }

    @Test
    public void testApduWithoutSelectedAppletFails() {
        Simulator simulator = new Simulator();
        byte[] cmd = new byte[]{CLA, INS_GET_FULL_AID, 0, 0};
        byte[] result;

        result = simulator.transmitCommand(cmd);
        assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, ByteUtil.getSW(result));
    }
}
