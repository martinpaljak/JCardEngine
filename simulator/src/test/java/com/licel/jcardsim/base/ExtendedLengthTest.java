// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2014 Robert Bachmann
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import com.licel.jcardsim.samples.Sha1Applet;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ExtendedLengthTest {
    private static final int CLA = 0x80;
    private static final int INS_DIGEST = 0x00;
    private static final int INS_ECHO = 0x02;
    private static final int INS_LEN = 0x04;
    private static final int P1 = 0x00;
    private static final int P2 = 0x00;
    private static final byte DUMMY = (byte) 0x41;

    private static final byte[] TEST_APPLET_AID_BYTES = Hex.decode("0102030405cafe01");
    private static final AID TEST_APPLET_AID = new AID(TEST_APPLET_AID_BYTES, (short) 0, (byte) TEST_APPLET_AID_BYTES.length);


    private Simulator prepareSimulator() {
        Simulator instance = new Simulator();
        instance.installApplet(TEST_APPLET_AID, Sha1Applet.class);
        return instance;
    }

    @Test
    public void testRegularApduDigest() throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        byte[] expectedOutput = sha1.digest(new byte[]{DUMMY});

        Simulator instance = prepareSimulator();

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(TEST_APPLET_AID));
            assertEquals(0x9000, sel.getSW());

            var responseApdu = bibo.transmit(new CommandAPDU(CLA, INS_DIGEST, P1, P2, new byte[]{DUMMY}));
            assertEquals(0x9000, responseApdu.getSW());
            assertEquals(Arrays.toString(expectedOutput), Arrays.toString(responseApdu.getData()));
        }
    }

    @Test
    public void testRegularApduLcLe() {
        byte lc = 1;
        byte le = (byte) 0xA0;
        byte[] expectedOutput = new byte[]{0, lc, 0, le};

        Simulator instance = prepareSimulator();

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(TEST_APPLET_AID));
            assertEquals(0x9000, sel.getSW());

            // Encoding-specific: use transceive(byte[]) since the applet asserts on Lc/Le wire bytes.
            var responseApdu = new ResponseAPDU(bibo.transceive(new byte[]{(byte) CLA, (byte) INS_LEN, (byte) P1, (byte) P2, lc, 0, le}));
            assertEquals(0x9000, responseApdu.getSW());
            assertEquals(Arrays.toString(expectedOutput), Arrays.toString(responseApdu.getData()));
        }
    }

    @Test
    public void testRegularApduCase2Le() {
        byte le = (byte) 0x4;
        byte[] expectedOutput = new byte[]{0, 0, 0, le};

        Simulator instance = prepareSimulator();

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(TEST_APPLET_AID));
            assertEquals(0x9000, sel.getSW());

            // Encoding-specific: use transceive(byte[]) since the applet asserts on Lc/Le wire bytes.
            var responseApdu = new ResponseAPDU(bibo.transceive(new byte[]{(byte) CLA, (byte) INS_LEN, (byte) P1, (byte) P2, le}));
            assertEquals(0x9000, responseApdu.getSW());
            assertEquals(Arrays.toString(expectedOutput), Arrays.toString(responseApdu.getData()));
        }
    }

    @Test
    public void testRegularApduEcho() throws NoSuchAlgorithmException {
        byte[] expectedOutput = new byte[]{DUMMY};

        Simulator instance = prepareSimulator();

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(TEST_APPLET_AID));
            assertEquals(0x9000, sel.getSW());

            var responseApdu = bibo.transmit(new CommandAPDU(CLA, INS_ECHO, 0x00, 0x00, new byte[]{DUMMY}));
            assertEquals(0x9000, responseApdu.getSW());
            assertEquals(Arrays.toString(expectedOutput), Arrays.toString(responseApdu.getData()));
        }
    }

    @Test
    public void testExtendedApduDigestWith1Byte() throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        byte[] input = new byte[]{DUMMY};
        byte[] expectedOutput = sha1.digest(input);

        Simulator instance = prepareSimulator();

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(TEST_APPLET_AID));
            assertEquals(0x9000, sel.getSW());

            var responseApdu = bibo.transmit(new CommandAPDU(CLA, INS_DIGEST, 0x00, 0x00, new byte[]{DUMMY}));
            assertEquals(0x9000, responseApdu.getSW());
            assertEquals(Arrays.toString(expectedOutput), Arrays.toString(responseApdu.getData()));
        }
    }

    @Test
    public void testExtendedApduCase2Le4() {
        byte le = (byte) 0x4;
        byte[] expectedOutput = new byte[]{0, 0, 0, le};

        Simulator instance = prepareSimulator();

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(TEST_APPLET_AID));
            assertEquals(0x9000, sel.getSW());

            // Encoding-specific: use transceive(byte[]) since the applet asserts on extended Le wire bytes.
            var responseApdu = new ResponseAPDU(bibo.transceive(new byte[]{(byte) CLA, (byte) INS_LEN, (byte) P1, (byte) P2, 0, 0, le}));
            assertEquals(0x9000, responseApdu.getSW());
            assertEquals(Arrays.toString(expectedOutput), Arrays.toString(responseApdu.getData()));
        }
    }

    @Test
    public void testExtendedApduCase2Le() {
        byte[] expectedOutput = new byte[]{0, 0, 1, 2};

        Simulator instance = prepareSimulator();

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(TEST_APPLET_AID));
            assertEquals(0x9000, sel.getSW());

            // Encoding-specific: use transceive(byte[]) since the applet asserts on extended Le wire bytes.
            var responseApdu = new ResponseAPDU(bibo.transceive(new byte[]{(byte) CLA, (byte) INS_LEN, (byte) P1, (byte) P2, 0, 1, 2}));
            assertEquals(0x9000, responseApdu.getSW());
            assertEquals(Arrays.toString(expectedOutput), Arrays.toString(responseApdu.getData()));
        }
    }

    @Test
    public void testExtendedApduLcLe() {
        byte[] expectedOutput = {0x0, 0x1, 0x1F, (byte) 0xCA};

        Simulator instance = prepareSimulator();

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(TEST_APPLET_AID));
            assertEquals(0x9000, sel.getSW());

            // Encoding-specific: use transceive(byte[]) since the applet asserts on extended Lc/Le wire bytes.
            var responseApdu = new ResponseAPDU(bibo.transceive(new byte[]{(byte) CLA, (byte) INS_LEN, (byte) P1, (byte) P2, 0, 0, 1, DUMMY, 0x1F, (byte) 0xCA}));
            assertEquals(0x9000, responseApdu.getSW());
            assertEquals(Arrays.toString(expectedOutput), Arrays.toString(responseApdu.getData()));
        }
    }

    @Test
    public void testExtendedApduEchoWith1Byte() throws NoSuchAlgorithmException {
        byte[] expectedOutput = {0x41};

        Simulator instance = prepareSimulator();

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(TEST_APPLET_AID));
            assertEquals(0x9000, sel.getSW());

            var responseApdu = bibo.transmit(new CommandAPDU(CLA, INS_ECHO, 0x00, 0x00, new byte[]{DUMMY}));
            assertEquals(0x9000, responseApdu.getSW());
            assertEquals(Arrays.toString(expectedOutput), Arrays.toString(responseApdu.getData()));
        }
    }

    @Test
    public void testExtendedApduDigest() throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        byte[] input = new byte[Short.MAX_VALUE];
        Arrays.fill(input, DUMMY);
        byte[] expectedOutput = sha1.digest(input);

        Simulator instance = prepareSimulator();

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(TEST_APPLET_AID));
            assertEquals(0x9000, sel.getSW());

            var responseApdu = bibo.transmit(new CommandAPDU(CLA, INS_DIGEST, P1, P2, input));
            assertEquals(0x9000, responseApdu.getSW());
            assertEquals(Arrays.toString(expectedOutput), Arrays.toString(responseApdu.getData()));
        }
    }
}
