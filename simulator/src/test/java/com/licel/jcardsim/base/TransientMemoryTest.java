// SPDX-FileCopyrightText: 2022 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.samples.Sha1Applet;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import org.testng.annotations.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.testng.Assert.*;

public class TransientMemoryTest {
    private static final int CLA = 0x80;
    private static final int INS_DIGEST = 0x00;
    private static final int INS_LAST_DIGEST = 0x06;

    @Test
    public void testMemoryManagementWorks() {
        final Object dummy1 = new Object();

        final short size = 1;
        TransientMemory transientMemory = new TransientMemory();

        byte[] corBytes = transientMemory.makeByteArray(size, JCSystem.CLEAR_ON_RESET, null);
        short[] corShorts = transientMemory.makeShortArray(size, JCSystem.CLEAR_ON_RESET, null);
        boolean[] corBooleans = transientMemory.makeBooleanArray(size, JCSystem.CLEAR_ON_RESET, null);

        Object[] corObjects = transientMemory.makeObjectArray(size, JCSystem.CLEAR_ON_RESET, null);
        corBytes[0] = 123;
        corShorts[0] = 123;
        corBooleans[0] = true;
        corObjects[0] = dummy1;

        byte[] codBytes = transientMemory.makeByteArray(size, JCSystem.CLEAR_ON_DESELECT, null);
        short[] codShorts = transientMemory.makeShortArray(size, JCSystem.CLEAR_ON_DESELECT, null);
        boolean[] codBooleans = transientMemory.makeBooleanArray(size, JCSystem.CLEAR_ON_DESELECT, null);

        Object[] codObjects = transientMemory.makeObjectArray(size, JCSystem.CLEAR_ON_DESELECT, null);
        codBytes[0] = 123;
        codShorts[0] = 123;
        codBooleans[0] = true;
        codObjects[0] = dummy1;

        transientMemory.clearOnDeselect();
        assertTrue(codBytes[0] == 0 && corBytes[0] != 0);
        assertTrue(codShorts[0] == 0 && corShorts[0] != 0);
        assertTrue(codObjects[0] == null && corObjects[0] == dummy1);
        assertTrue(!codBooleans[0] && corBooleans[0]);

        codBytes[0] = 123;
        codShorts[0] = 123;
        codBooleans[0] = true;
        codObjects[0] = dummy1;

        transientMemory.clearOnReset();
        assertTrue(codBytes[0] == 0 && corBytes[0] == 0);
        assertTrue(codShorts[0] == 0 && corShorts[0] == 0);
        assertTrue(codObjects[0] == null && corObjects[0] == null);
        assertTrue(!codBooleans[0] && !corBooleans[0]);

        assertEquals(transientMemory.isTransient(corBytes), JCSystem.CLEAR_ON_RESET);
        assertEquals(transientMemory.isTransient(corShorts), JCSystem.CLEAR_ON_RESET);
        assertEquals(transientMemory.isTransient(corBooleans), JCSystem.CLEAR_ON_RESET);
        assertEquals(transientMemory.isTransient(corObjects), JCSystem.CLEAR_ON_RESET);

        assertEquals(transientMemory.isTransient(codBytes), JCSystem.CLEAR_ON_DESELECT);
        assertEquals(transientMemory.isTransient(codShorts), JCSystem.CLEAR_ON_DESELECT);
        assertEquals(transientMemory.isTransient(codBooleans), JCSystem.CLEAR_ON_DESELECT);
        assertEquals(transientMemory.isTransient(codObjects), JCSystem.CLEAR_ON_DESELECT);
    }

    @Test
    public void clearOnDeselectIsContextScoped() {
        var sim = new Simulator();
        var aidA = AIDUtil.create("a00000001101");
        var aidB = AIDUtil.create("b00000002202");
        sim.installApplet(aidA, Sha1Applet.class);
        sim.installApplet(aidB, Sha1Applet.class);
        var ctxA = sim.gp().lookup(aidA).getContext();
        var ctxB = sim.gp().lookup(aidB).getContext();
        assertNotSame(ctxA, ctxB);

        var tm = sim.getTransientMemory();
        byte[] a = tm.makeByteArray(4, JCSystem.CLEAR_ON_DESELECT, ctxA);
        byte[] b = tm.makeByteArray(4, JCSystem.CLEAR_ON_DESELECT, ctxB);
        a[0] = 0x11;
        b[0] = 0x22;

        // Single-channel selection never leaves two applets selected, so the deselect event is driven directly.
        tm.clearOnDeselect(ctxA);
        // JCRE 3.2 5.1.2: the event clears the CLEAR_ON_DESELECT arrays of the deselected context only.
        assertEquals(a[0], 0);
        assertEquals(b[0], 0x22);
    }


    @Test
    public void testInvalidEventThrows() {
        final byte invalid = JCSystem.CLEAR_ON_DESELECT + JCSystem.CLEAR_ON_RESET;
        TransientMemory transientMemory = new TransientMemory();

        try {
            transientMemory.makeByteArray(2, invalid, null);
            fail("No exception");
        } catch (SystemException e) {
            assertEquals(e.getReason(), SystemException.ILLEGAL_VALUE);
        }

        try {
            transientMemory.makeBooleanArray((short) 1, invalid, null);
            fail("No exception");
        } catch (SystemException e) {
            assertEquals(e.getReason(), SystemException.ILLEGAL_VALUE);
        }

        try {
            transientMemory.makeObjectArray((short) 1, invalid, null);
            fail("No exception");
        } catch (SystemException e) {
            assertEquals(e.getReason(), SystemException.ILLEGAL_VALUE);
        }

        try {
            transientMemory.makeShortArray((short) 1, invalid, null);
            fail("No exception");
        } catch (SystemException e) {
            assertEquals(e.getReason(), SystemException.ILLEGAL_VALUE);
        }
    }

    @Test
    public void testCleanOnDeselectWorks() throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        byte[] expectedOutput = sha1.digest(new byte[]{'A'});
        AID aid = AIDUtil.create("0102030405");

        Simulator instance = new Simulator();
        instance.installApplet(aid, Sha1Applet.class);

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(aid));
            assertEquals(sel.getSW(), 0x9000);

            // calculate SHA1
            var responseApdu = bibo.transmit(new CommandAPDU(CLA, INS_DIGEST, 0x00, 0x00, new byte[]{'A'}));
            assertEquals(responseApdu.getSW(), 0x9000);
            assertEquals(responseApdu.getData(), expectedOutput);

            // check last digest
            responseApdu = bibo.transmit(new CommandAPDU(CLA, INS_LAST_DIGEST, 0x00, 0x00));
            assertEquals(responseApdu.getSW(), 0x9000);
            assertEquals(responseApdu.getData(), expectedOutput);

            // trigger clean on deselect
            bibo.transmit(AIDUtil.select(aid));

            // check last digest is all zero
            responseApdu = bibo.transmit(new CommandAPDU(CLA, INS_LAST_DIGEST, 0x00, 0x00));
            assertEquals(responseApdu.getSW(), 0x9000);
            assertEquals(responseApdu.getData(), new byte[20]);
        }
    }

    @Test
    public void transientKeyClearsInitializedState() {
        var sim = new Simulator();
        try (var current = sim.asCurrent()) {
            AESKey key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);
            key.setKey(new byte[16], (short) 0);
            assertTrue(key.isInitialized());

            sim.getTransientMemory().clearOnReset();
            // The initialized state lives in the same transient memory as the key bytes, so the event
            // leaves the key uninitialized rather than merely zeroed.
            assertFalse(key.isInitialized());
            assertThrows(CryptoException.class, () -> key.getKey(new byte[16], (short) 0));
        }
    }

    @Test
    public void testGlobalArrayBooleanType() {
        final short size = 1;

        TransientMemory transientMemory = new TransientMemory();
        boolean[] globalBooleans = (boolean[]) transientMemory.makeGlobalArray(JCSystem.ARRAY_TYPE_BOOLEAN, size);
        globalBooleans[0] = true;

        transientMemory.clearOnDeselect();
        assertTrue(globalBooleans[0]);

        transientMemory.clearOnReset();
        assertFalse(globalBooleans[0]);
    }

    @Test
    public void testGlobalArrayByteType() {
        final short size = 1;

        TransientMemory transientMemory = new TransientMemory();
        byte[] globalBytes = (byte[]) transientMemory.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, size);
        globalBytes[0] = (byte) 0x5A;

        transientMemory.clearOnDeselect();
        assertEquals(globalBytes[0], 0x5A);

        transientMemory.clearOnReset();
        assertEquals(globalBytes[0], 0);
    }

    @Test
    public void testGlobalArrayShortType() {
        final short size = 1;

        TransientMemory transientMemory = new TransientMemory();
        short[] globalShorts = (short[]) transientMemory.makeGlobalArray(JCSystem.ARRAY_TYPE_SHORT, size);
        globalShorts[0] = (short) 0x5A7F;

        transientMemory.clearOnDeselect();
        assertEquals(globalShorts[0], 0x5A7F);

        transientMemory.clearOnReset();
        assertEquals(globalShorts[0], 0);
    }

    @Test
    public void testGlobalArrayObjectType() {
        final Object dummy = new Object();

        final short size = 1;

        TransientMemory transientMemory = new TransientMemory();
        Object[] globalObjects = (Object[]) transientMemory.makeGlobalArray(JCSystem.ARRAY_TYPE_OBJECT, size);
        globalObjects[0] = dummy;

        transientMemory.clearOnDeselect();
        assertSame(globalObjects[0], dummy);

        transientMemory.clearOnReset();
        assertNull(globalObjects[0]);
    }

    @Test
    public void testGlobalArrayInvalidType() {
        final byte invalid = JCSystem.ARRAY_TYPE_INT;
        final short size = 1;
        TransientMemory transientMemory = new TransientMemory();

        try {
            transientMemory.makeGlobalArray(invalid, size);
            fail("No exception");
        } catch (SystemException e) {
            assertEquals(e.getReason(), SystemException.ILLEGAL_VALUE);
        }
    }
}
