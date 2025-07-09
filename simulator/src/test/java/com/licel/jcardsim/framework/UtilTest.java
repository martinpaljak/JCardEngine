package com.licel.jcardsim.framework;

import javacard.framework.Util;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class UtilTest {

    @Test
    public void testArrayCompare1() {
        byte[] src = new byte[]{0x01};
        byte[] dest = new byte[]{0x02};
        byte res = Util.arrayCompare(src, (short) 0, dest, (short) 0, (short) 1);
        assertEquals(-1, res);
    }

    @Test
    public void testArrayCompare2() {
        byte[] src = new byte[]{(byte) 0xff};
        byte[] dest = new byte[]{0x01};
        byte res = Util.arrayCompare(src, (short) 0, dest, (short) 0, (short) 1);
        assertEquals(1, res);
    }

    /**
     * Test of arrayFillNonAtomic method, of class Util.
     */
    @Test
    public void testArrayFillNonAtomic() {
        byte[] etalonArray = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0};
        byte[] bArray = new byte[16];
        short bOff = 8;
        short bLen = 7;
        byte bValue = 1;
        short expResult = (short) (bOff + bLen);
        short result = Util.arrayFillNonAtomic(bArray, bOff, bLen, bValue);
        assertEquals(expResult, result);
        byte res = Util.arrayCompare(bArray, (short) 0, etalonArray, (short) 0, (short) 16);
        assertEquals(0, res);
    }
}
