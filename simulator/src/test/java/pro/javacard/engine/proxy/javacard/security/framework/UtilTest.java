// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2013 Klas Lindfors
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.proxy.javacard.security.framework;

import javacard.framework.Util;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
        // Zero-length fill at the end of the array is a no-op, not AIOOBE
        assertEquals((short) bArray.length, Util.arrayFillNonAtomic(bArray, (short) bArray.length, (short) 0, bValue));

        // A non-zero fill running past the end of the array throws (bounds checked at bOff+bLen-1)
        assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> Util.arrayFillNonAtomic(bArray, (short) (bArray.length - 1), (short) 2, bValue));
    }
}
