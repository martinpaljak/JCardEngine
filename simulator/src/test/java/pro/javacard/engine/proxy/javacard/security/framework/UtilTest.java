// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2013 Klas Lindfors
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.proxy.javacard.security.framework;

import javacard.framework.Util;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class UtilTest {

    @DataProvider(name = "arrayCompareCases")
    public static Object[][] arrayCompareCases() {
        return new Object[][] {
                // Identical arrays
                { new byte[]{0x01}, new byte[]{0x01}, (byte) 0 },
                { new byte[]{0x01, 0x02}, new byte[]{0x01, 0x02}, (byte) 0 },
                { new byte[0], new byte[0], (byte) 0 },

                // Plain ordering
                { new byte[]{0x01}, new byte[]{0x02}, (byte) -1 },
                { new byte[]{0x02}, new byte[]{0x01}, (byte) 1 },

                // Signed comparison: 0xff is -1, 0x80 is -128
                { new byte[]{(byte) 0xff}, new byte[]{0x01}, (byte) -1 },
                { new byte[]{0x01}, new byte[]{(byte) 0xff}, (byte) 1 },
                { new byte[]{(byte) 0x80}, new byte[]{0x7f}, (byte) -1 },
                { new byte[]{0x7f}, new byte[]{(byte) 0x80}, (byte) 1 },
                { new byte[]{0x00}, new byte[]{(byte) 0xff}, (byte) 1 },

                // Only the first differing byte decides
                { new byte[]{0x02, 0x00}, new byte[]{0x01, 0x7f}, (byte) 1 },
                { new byte[]{0x01, (byte) 0xff}, new byte[]{0x01, 0x01}, (byte) -1 }
        };
    }

    @Test(dataProvider = "arrayCompareCases")
    public void testArrayCompareParameterised(byte[] src, byte[] dest, byte expected) {
        assertEquals(Util.arrayCompare(src, (short) 0, dest, (short) 0, (short) src.length), expected);
    }

    @Test
    public void testArrayCompareWithOffsets() {
        byte[] src = new byte[]{0x01, 0x10, 0x20};
        byte[] dest = new byte[]{0x02, 0x10, 0x30};

        // Differing prefix before the offset is ignored
        assertEquals(Util.arrayCompare(src, (short) 1, dest, (short) 1, (short) 1), (byte) 0);

        // Difference inside the window is found
        assertEquals(Util.arrayCompare(src, (short) 1, dest, (short) 1, (short) 2), (byte) -1);

        // Signed comparison applies at the offset too: 0xff (-1) < 0x01
        byte[] signedSrc = new byte[]{0x00, (byte) 0xff};
        byte[] signedDest = new byte[]{0x00, 0x01};
        assertEquals(Util.arrayCompare(signedSrc, (short) 1, signedDest, (short) 1, (short) 1), (byte) -1);
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
        assertEquals(result, expResult);
        byte res = Util.arrayCompare(bArray, (short) 0, etalonArray, (short) 0, (short) 16);
        assertEquals(res, 0);
        // Zero-length fill at the end of the array is a no-op, not AIOOBE
        assertEquals(Util.arrayFillNonAtomic(bArray, (short) bArray.length, (short) 0, bValue), (short) bArray.length);

        // A non-zero fill running past the end of the array throws (bounds checked at bOff+bLen-1)
        assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> Util.arrayFillNonAtomic(bArray, (short) (bArray.length - 1), (short) 2, bValue));
    }
}
