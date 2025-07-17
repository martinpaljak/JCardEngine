/*
 * Copyright 2016 Licel Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package pro.javacard.engine.proxy.javacard.security.framework;


import com.licel.jcardsim.SimulatorCoreTest;
import javacard.framework.OwnerPIN;
import javacard.framework.PINException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class OwnerPinTest extends SimulatorCoreTest {

    @Test
    public void testConstructor1() {
        boolean isException = false;
        try {
            OwnerPIN o = new OwnerPIN((byte) 0, (byte) 1);
        } catch (Exception e) {
            assertEquals(true, (e instanceof PINException));
            assertEquals(PINException.ILLEGAL_VALUE, ((PINException) e).getReason());
            isException = true;
        }
        assertEquals(true, isException);
    }

    @Test
    public void testConstructor2() {
        boolean isException = false;
        try {
            OwnerPIN o = new OwnerPIN((byte) 1, (byte) 0);
        } catch (Exception e) {
            assertEquals(true, (e instanceof PINException));
            assertEquals(PINException.ILLEGAL_VALUE, ((PINException) e).getReason());
            isException = true;
        }
        assertEquals(true, isException);
    }

    @Test
    public void testConstructor3() {
        byte tries = 3;
        OwnerPIN o = new OwnerPIN(tries, (byte) 16);
        assertEquals(tries, o.getTriesRemaining());
    }

    @Test
    public void testConstructor4() {
        boolean isException = false;
        try {
            OwnerPIN o = new OwnerPIN((byte) 3, (byte) 16);
            byte[] pin = new byte[17];
            o.update(pin, (short) 0, (byte) pin.length);
        } catch (Exception e) {
            assertEquals(true, (e instanceof PINException));
            assertEquals(PINException.ILLEGAL_VALUE, ((PINException) e).getReason());
            isException = true;
        }
        assertEquals(true, isException);
    }

    @Test
    public void testUpdate() {
        byte tries = 3;
        byte[] pin = new byte[]{(byte) 0, (byte) 1, (byte) 3};
        OwnerPIN o = new OwnerPIN(tries, (byte) 3);
        o.update(pin, (short) 0, (byte) pin.length);
        assertEquals(true, o.check(pin, (short) 0, (byte) pin.length));
        assertEquals(tries, o.getTriesRemaining());
    }

    @Test
    public void testCheck() {
        byte tries = 4;
        byte[] pin = new byte[]{(byte) 0, (byte) 1, (byte) 3};
        byte[] pin2 = new byte[]{(byte) 0, (byte) 1, (byte) 2};
        OwnerPIN o = new OwnerPIN(tries, (byte) 3);
        o.update(pin, (short) 0, (byte) pin.length);
        // correct
        assertEquals(true, o.check(pin, (short) 0, (byte) pin.length));
        assertEquals(tries, o.getTriesRemaining());
        assertEquals(true, o.isValidated());
        // incorrect
        assertEquals(false, o.check(pin2, (short) 0, (byte) pin2.length));
        assertEquals(tries - 1, o.getTriesRemaining());
        assertEquals(false, o.isValidated());
        // incorrect
        assertEquals(false, o.check(pin2, (short) 0, (byte) (pin2.length - 1)));
        assertEquals(tries - 2, o.getTriesRemaining());
        assertEquals(false, o.isValidated());
        // incorrect
        try {
            assertEquals(false, o.check(null, (short) 0, (byte) (pin2.length)));
        } catch (Exception e) {
            assertEquals(true, (e instanceof NullPointerException));
        }
        assertEquals(tries - 3, o.getTriesRemaining());
        assertEquals(false, o.isValidated());
        // incorrect
        try {
            assertEquals(false, o.check(pin2, (short) 0, (byte) (pin2.length + 1)));
        } catch (Exception e) {
            assertEquals(true, (e instanceof ArrayIndexOutOfBoundsException));
        }
        assertEquals(0, o.getTriesRemaining());
        assertEquals(false, o.isValidated());
    }

    @Test
    public void testReset1() {
        byte tries = 1;
        byte[] pin = new byte[]{(byte) 0, (byte) 1, (byte) 3};
        byte[] pin2 = new byte[]{(byte) 0, (byte) 1, (byte) 2};
        OwnerPIN o = new OwnerPIN(tries, (byte) 3);
        o.update(pin, (short) 0, (byte) pin.length);
        assertEquals(false, o.check(pin2, (short) 0, (byte) pin2.length));
        assertEquals(0, o.getTriesRemaining());
        o.reset();
        assertEquals(0, o.getTriesRemaining());
    }

    @Test
    public void testReset2() {
        byte tries = 2;
        byte[] pin = new byte[]{(byte) 0, (byte) 1, (byte) 3};
        byte[] pin2 = new byte[]{(byte) 0, (byte) 1, (byte) 2};
        OwnerPIN o = new OwnerPIN(tries, (byte) 3);
        o.update(pin, (short) 0, (byte) pin.length);
        assertEquals(false, o.check(pin2, (short) 0, (byte) pin2.length));
        assertEquals(tries - 1, o.getTriesRemaining());
        assertEquals(true, o.check(pin, (short) 0, (byte) pin.length));
        o.reset();
        assertEquals(tries, o.getTriesRemaining());
    }

    @Test
    public void testResetAndUnblock() {
        byte tries = 1;
        byte[] pin = new byte[]{(byte) 0, (byte) 1, (byte) 3};
        byte[] pin2 = new byte[]{(byte) 0, (byte) 1, (byte) 2};
        OwnerPIN o = new OwnerPIN(tries, (byte) 3);
        o.update(pin, (short) 0, (byte) pin.length);
        assertEquals(false, o.check(pin2, (short) 0, (byte) pin2.length));
        assertEquals(0, o.getTriesRemaining());
        o.resetAndUnblock();
        assertEquals(tries, o.getTriesRemaining());
        assertEquals(false, o.isValidated());
    }

}
