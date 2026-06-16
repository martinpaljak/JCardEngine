// SPDX-FileCopyrightText: 2016 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.proxy.javacard.security.framework;


import com.licel.jcardsim.SimulatorCoreTest;
import javacard.framework.OwnerPIN;
import javacard.framework.PINException;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class OwnerPinTest extends SimulatorCoreTest {

    @Test
    public void testConstructor1() {
        boolean isException = false;
        try {
            OwnerPIN o = new OwnerPIN((byte) 0, (byte) 1);
        } catch (Exception e) {
            assertTrue(e instanceof PINException);
            assertEquals(((PINException) e).getReason(), PINException.ILLEGAL_VALUE);
            isException = true;
        }
        assertTrue(isException);
    }

    @Test
    public void testConstructor2() {
        boolean isException = false;
        try {
            OwnerPIN o = new OwnerPIN((byte) 1, (byte) 0);
        } catch (Exception e) {
            assertTrue(e instanceof PINException);
            assertEquals(((PINException) e).getReason(), PINException.ILLEGAL_VALUE);
            isException = true;
        }
        assertTrue(isException);
    }

    @Test
    public void testConstructor3() {
        byte tries = 3;
        OwnerPIN o = new OwnerPIN(tries, (byte) 16);
        assertEquals(o.getTriesRemaining(), tries);
    }

    @Test
    public void testConstructor4() {
        boolean isException = false;
        try {
            OwnerPIN o = new OwnerPIN((byte) 3, (byte) 16);
            byte[] pin = new byte[17];
            o.update(pin, (short) 0, (byte) pin.length);
        } catch (Exception e) {
            assertTrue(e instanceof PINException);
            assertEquals(((PINException) e).getReason(), PINException.ILLEGAL_VALUE);
            isException = true;
        }
        assertTrue(isException);
    }

    @Test
    public void testUpdate() {
        byte tries = 3;
        byte[] pin = new byte[]{(byte) 0, (byte) 1, (byte) 3};
        OwnerPIN o = new OwnerPIN(tries, (byte) 3);
        o.update(pin, (short) 0, (byte) pin.length);
        assertTrue(o.check(pin, (short) 0, (byte) pin.length));
        assertEquals(o.getTriesRemaining(), tries);
    }

    @Test
    public void testCheck() {
        byte tries = 4;
        byte[] pin = new byte[]{(byte) 0, (byte) 1, (byte) 3};
        byte[] pin2 = new byte[]{(byte) 0, (byte) 1, (byte) 2};
        OwnerPIN o = new OwnerPIN(tries, (byte) 3);
        o.update(pin, (short) 0, (byte) pin.length);
        // correct
        assertTrue(o.check(pin, (short) 0, (byte) pin.length));
        assertEquals(o.getTriesRemaining(), tries);
        assertTrue(o.isValidated());
        // incorrect
        assertFalse(o.check(pin2, (short) 0, (byte) pin2.length));
        assertEquals(o.getTriesRemaining(), tries - 1);
        assertFalse(o.isValidated());
        // incorrect
        assertFalse(o.check(pin2, (short) 0, (byte) (pin2.length - 1)));
        assertEquals(o.getTriesRemaining(), tries - 2);
        assertFalse(o.isValidated());
        // incorrect
        try {
            assertFalse(o.check(null, (short) 0, (byte) (pin2.length)));
        } catch (Exception e) {
            assertTrue(e instanceof NullPointerException);
        }
        assertEquals(o.getTriesRemaining(), tries - 3);
        assertFalse(o.isValidated());
        // incorrect
        try {
            assertFalse(o.check(pin2, (short) 0, (byte) (pin2.length + 1)));
        } catch (Exception e) {
            assertTrue(e instanceof ArrayIndexOutOfBoundsException);
        }
        assertEquals(o.getTriesRemaining(), 0);
        assertFalse(o.isValidated());
    }

    @Test
    public void testReset1() {
        byte tries = 1;
        byte[] pin = new byte[]{(byte) 0, (byte) 1, (byte) 3};
        byte[] pin2 = new byte[]{(byte) 0, (byte) 1, (byte) 2};
        OwnerPIN o = new OwnerPIN(tries, (byte) 3);
        o.update(pin, (short) 0, (byte) pin.length);
        assertFalse(o.check(pin2, (short) 0, (byte) pin2.length));
        assertEquals(o.getTriesRemaining(), 0);
        o.reset();
        assertEquals(o.getTriesRemaining(), 0);
    }

    @Test
    public void testReset2() {
        byte tries = 2;
        byte[] pin = new byte[]{(byte) 0, (byte) 1, (byte) 3};
        byte[] pin2 = new byte[]{(byte) 0, (byte) 1, (byte) 2};
        OwnerPIN o = new OwnerPIN(tries, (byte) 3);
        o.update(pin, (short) 0, (byte) pin.length);
        assertFalse(o.check(pin2, (short) 0, (byte) pin2.length));
        assertEquals(o.getTriesRemaining(), tries - 1);
        assertTrue(o.check(pin, (short) 0, (byte) pin.length));
        o.reset();
        assertEquals(o.getTriesRemaining(), tries);
    }

    @Test
    public void testResetAndUnblock() {
        byte tries = 1;
        byte[] pin = new byte[]{(byte) 0, (byte) 1, (byte) 3};
        byte[] pin2 = new byte[]{(byte) 0, (byte) 1, (byte) 2};
        OwnerPIN o = new OwnerPIN(tries, (byte) 3);
        o.update(pin, (short) 0, (byte) pin.length);
        assertFalse(o.check(pin2, (short) 0, (byte) pin2.length));
        assertEquals(o.getTriesRemaining(), 0);
        o.resetAndUnblock();
        assertEquals(o.getTriesRemaining(), tries);
        assertFalse(o.isValidated());
    }

}
