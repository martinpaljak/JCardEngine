/*
 * Copyright 2014 Robert Bachmann
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
package com.licel.jcardsim.utils;

import java.util.HexFormat;

/**
 * Utility methods for dealing with byte arrays.
 */
public final class ByteUtil {

    public static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    public static byte[] hex(String str) {
        return HexFormat.of().parseHex(str);
    }

    /**
     * Extract status word from APDU
     *
     * @param apduBuffer APDU bytes
     * @return status word
     * @throws java.lang.NullPointerException     if <code>apduBuffer</code> is null
     * @throws java.lang.IllegalArgumentException if <code>apduBuffer.length</code>  is &lt; 2
     */
    public static short getSW(byte[] apduBuffer) {
        if (apduBuffer == null) {
            throw new NullPointerException("bytes");
        }
        if (apduBuffer.length < 2) {
            throw new IllegalArgumentException("bytes.length must be at least 2");
        }
        return getShort(apduBuffer, apduBuffer.length - 2);
    }

    /**
     * Read short from array
     *
     * @param bArray byte array
     * @param offset offset
     * @return short value
     * @see javacard.framework.Util#getShort(byte[], short)
     */
    public static short getShort(byte[] bArray, int offset) {
        return (short) (((short) bArray[offset] << 8) + ((short) bArray[offset + 1] & 0xff));
    }

    private ByteUtil() {
    }
}
