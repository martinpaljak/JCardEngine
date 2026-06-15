// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2014 Robert Bachmann
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.samples.MultiInstanceApplet;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.*;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.testapplets.GlobalPlatformTestApplet;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class SelectTest {
    private static final byte CLA = (byte) 0x80;
    private static final byte INS_GET_FULL_AID = 0;


    public static class UnselectableApplet extends Applet {
        public static boolean selectedCalled;

        private final byte[] array = new byte[12];

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

    // Returns true from select() while leaving an applet-initiated transaction
    // open - the JCRE must treat this as a selection failure.
    public static class TransactionLeakingApplet extends Applet {
        @SuppressWarnings("unused")
        public static void install(byte[] bArray, short bOffset, byte bLength) {
            new TransactionLeakingApplet().register();
        }

        @Override
        public boolean select() {
            JCSystem.beginTransaction();
            return true;
        }

        @Override
        public void process(APDU apdu) throws ISOException {
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

        try (var bibo = simulator.connect()) {
            // should select d0000cafe00001
            var sel = bibo.transmit(AIDUtil.select(AIDUtil.create("d0000cafe0")));
            assertEquals(0x9000, sel.getSW());
            byte[] expected = Hex.decode("d0000cafe000019000");
            var actual = bibo.transmit(new CommandAPDU(CLA, INS_GET_FULL_AID, 0, 0));
            assertEquals(Arrays.toString(expected), Arrays.toString(actual.getBytes()));

            // GPC v2.3.1 6.4.2.1.2: SELECT [by name] [next occurrence] (P2 b2) walks past the first partial
            // match to the next one - d0000cafe00002.
            var next = bibo.transmit(new CommandAPDU(0x00, ISO7816.INS_SELECT, 0x04, 0x02, Hex.decode("d0000cafe0")));
            assertEquals(0x9000, next.getSW());
            byte[] expectedNext = Hex.decode("d0000cafe000029000");
            var actualNext = bibo.transmit(new CommandAPDU(CLA, INS_GET_FULL_AID, 0, 0));
            assertEquals(Arrays.toString(expectedNext), Arrays.toString(actualNext.getBytes()));
        }
    }

    // GPC v2.3.1 6.4.2.1.2: SELECT [by name] [next occurrence] (P2 b2) walks the registry after the
    // currently selected Application, skipping LOCKED entries, until it finds the next partial match or
    // runs out. Prefix d0000cafe000 holds aa (match), bb (locked - skipped), cc (match); e0... is an
    // unrelated AID iterated after cc so the second walk runs past it and exhausts the search.
    @Test
    public void testNextOccurrenceSkipsLockedAndExhausts() {
        AID aa = AIDUtil.create("d0000cafe000aa");
        AID bb = AIDUtil.create("d0000cafe000bb");
        AID cc = AIDUtil.create("d0000cafe000cc");
        AID other = AIDUtil.create("e000000000");

        Simulator simulator = new Simulator();
        simulator.installApplet(aa, MultiInstanceApplet.class);
        simulator.installApplet(bb, GlobalPlatformTestApplet.class);
        simulator.installApplet(cc, MultiInstanceApplet.class);
        simulator.installApplet(other, MultiInstanceApplet.class);

        try (var bibo = simulator.connect()) {
            // Self-lock bb via the GP test applet's setState(0x83) instruction: b8=1 marks it LOCKED.
            bibo.transmit(AIDUtil.select(bb));
            var lock = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS_VIA_REGISTRY, 0x83, 0x00, 256));
            assertEquals(0x9000, lock.getSW());
            assertEquals((byte) 0x01, lock.getData()[0]);

            // Full-AID select aa, then next-occurrence over the shared prefix: bb is LOCKED so the
            // search skips it and lands on cc.
            assertEquals(0x9000, bibo.transmit(AIDUtil.select(aa)).getSW());
            var next = bibo.transmit(new CommandAPDU(0x00, ISO7816.INS_SELECT, 0x04, 0x02, Hex.decode("d0000cafe000")));
            assertEquals(0x9000, next.getSW());
            byte[] onCc = bibo.transmit(new CommandAPDU(CLA, INS_GET_FULL_AID, 0, 0)).getData();
            assertArrayEquals(AIDUtil.bytes(cc), onCc);

            // From cc, next-occurrence over the same prefix finds no further match: the walk runs past
            // the unrelated e0... entry and exhausts, so the SELECT is dispatched to the current applet
            // (cc, a MultiInstanceApplet) which rejects the ISO-class SELECT with 6E00 and stays selected.
            var miss = bibo.transmit(new CommandAPDU(0x00, ISO7816.INS_SELECT, 0x04, 0x02, Hex.decode("d0000cafe000")));
            assertEquals(0x6E00, miss.getSW());
            byte[] stillCc = bibo.transmit(new CommandAPDU(CLA, INS_GET_FULL_AID, 0, 0)).getData();
            assertArrayEquals(AIDUtil.bytes(cc), stillCc);
        }
    }

    @Test
    public void testPartialSelectWorks2() {
        Simulator simulator = prepareSimulator();

        try (var bibo = simulator.connect()) {
            // should select d0000cafe00001
            bibo.transmit(new CommandAPDU(0x00, ISO7816.INS_SELECT, 0x04, 0x00, new byte[]{(byte) 0xD0}));

            byte[] expected = Hex.decode("d0000cafe000019000");
            var actual = bibo.transmit(new CommandAPDU(CLA, INS_GET_FULL_AID, 0, 0));
            assertEquals(Arrays.toString(expected), Arrays.toString(actual.getBytes()));
        }
    }

    @Test
    public void testEmptySelectWorks() {
        // GPC v2.3.1 6.3: empty-AID SELECT (case 1/2) selects the default application - the ISD, which
        // every card is now born with - so it answers with its FCI and 9000, not "not found".
        Simulator simulator = prepareSimulator();
        try (var bibo = simulator.connect()) {
            var actual = bibo.transmit(new CommandAPDU(0x00, ISO7816.INS_SELECT, 0x04, 0x00));
            assertEquals(0x9000, actual.getSW());
        }
    }

    @Test
    public void testCanNotSelectUnselectableApplet() {
        AID aid = AIDUtil.create("010203040506070809");
        Simulator simulator = new Simulator();
        simulator.installExposedApplet(aid, UnselectableApplet.class);

        byte[] result = simulator.transceive(AIDUtil.selectBytes(aid));
        assertEquals(2, result.length);
        assertEquals(ISO7816.SW_APPLET_SELECT_FAILED, Util.getShort(result, (short) 0));
        assertTrue(UnselectableApplet.selectedCalled);
    }

    // JCRE 3.2 4.6.2 step 7: select() returning true with a transaction
    // in progress is a selection failure (SW=6999) and no applet stays selected.
    @Test
    public void testSelectWithLeakedTransactionFails() {
        AID aid = AIDUtil.create("d0000cafe00099");
        Simulator simulator = new Simulator();
        simulator.installExposedApplet(aid, TransactionLeakingApplet.class);

        try (var bibo = simulator.connect()) {
            var sel = bibo.transmit(AIDUtil.select(aid));
            assertEquals(ISO7816.SW_APPLET_SELECT_FAILED, (short) sel.getSW());
            // No applet is active on the channel - JCRE 3.2 4.8 rejects subsequent non-SELECT with 6999.
            var follow = bibo.transmit(new CommandAPDU(CLA, INS_GET_FULL_AID, 0, 0));
            assertEquals(ISO7816.SW_APPLET_SELECT_FAILED, (short) follow.getSW());
        }
    }

    @Test
    public void testHostSelectWithLeakedTransactionFails() {
        AID aid = AIDUtil.create("d0000cafe00099");
        Simulator simulator = new Simulator();
        simulator.installExposedApplet(aid, TransactionLeakingApplet.class);

        try (var bibo = simulator.connect()) {
            // select() returning true with a transaction in progress is a selection failure
            var sel = bibo.transmit(AIDUtil.select(aid));
            assertEquals(0x6999, sel.getSW());
        }
    }

    // GPC v2.3.1 6.4.2.1.2: on SELECT lookup miss, the currently selected
    // Application shall remain selected.
    @Test
    public void testSelectAppletWithUnknownAidPreservesCurrent() {
        AID good = AIDUtil.create("d0000cafe00001");
        AID bad = AIDUtil.create("d0000cafe09999");

        Simulator simulator = new Simulator();
        simulator.installApplet(good, MultiInstanceApplet.class);

        try (var bibo = simulator.connect()) {
            assertEquals(0x9000, bibo.transmit(AIDUtil.select(good)).getSW());   // good selected
            // SELECT miss is dispatched to the current applet (good), not a reselection: good
            // rejects the ISO CLA of the SELECT command
            assertEquals(0x6E00, bibo.transmit(AIDUtil.select(bad)).getSW());
            // good is still selected
            var actual = bibo.transmit(new CommandAPDU(CLA, INS_GET_FULL_AID, 0, 0));
            assertEquals(0x9000, actual.getSW());
            assertArrayEquals(AIDUtil.bytes(good), actual.getData());
        }
    }
}
