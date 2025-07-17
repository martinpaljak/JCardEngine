/*
 * Copyright 2025 Martin Paljak <martin@martinpaljak.net>
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
package com.licel.jcardsim.base;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.Util;

import java.util.Locale;
import java.util.Objects;

/**
 * Case of an <code>APDU</code>.
 */
public final class APDUHelper {
    /**
     * Case 1 APDU (CLA, INS, P1, P2)
     */
    public static final int CASE1 = 0x01;
    /**
     * Case 2 APDU (CLA, INS, P1, P2, 1 byte Le)
     */
    public static final int CASE2 = 0x02;
    /**
     * Case 2 extended APDU (CLA, INS, P1, P2, 0, 2 byte Le)
     */
    public static final int CASE2_EXTENDED = 0x03;
    /**
     * Case 3 APDU (CLA, INS, P1, P2, 1 byte Lc, Data)
     */
    public static final int CASE3 = 0x04;
    /**
     * Case 3 extended APDU (CLA, INS, P1, P2, 2 byte Lc, Data)
     */
    public static final int CASE3_EXTENDED = 0x05;
    /**
     * Case 4 APDU (CLA, INS, P1, P2, 1 byte Lc, Data, 1 byte Le)
     */
    public static final int CASE4 = 0x06;
    /**
     * Case 4 extended APDU (CLA, INS, P1, P2, 0, 2 byte Lc, Data, 2 byte Le)
     */
    public static final int CASE4_EXTENDED = 0x07;


    /**
     * @return <code>true</code> for extended APDU
     */
    public static boolean isExtendedAPDU(int apducase) {
        switch (apducase) {
            case CASE2_EXTENDED:
            case CASE3_EXTENDED:
            case CASE4_EXTENDED:
                return true;
            default:
                return false;
        }
    }

    /**
     * Determine case of APDU
     * @param command command APDU byte buffer
     * @return Case of <code>command</code>
     * @throws java.lang.IllegalArgumentException if <code>command</code> is malformed
     * @throws java.lang.NullPointerException if <code>command</code> is null
     */
    public static int getAPDUCase(byte[] command) {
        Objects.requireNonNull(command);
        if (command.length < 4) {
            throw new IllegalArgumentException("command: malformed APDU, length < 4");
        }
        if (command.length == 4) {
            return CASE1;
        }
        if (command.length == 5) {
            return CASE2;
        }
        if (command.length == 7 && command[ISO7816.OFFSET_LC] == 0) {
            return CASE2_EXTENDED;
        }
        if (command[ISO7816.OFFSET_LC] == 0) {
            int lc = Util.getShort(command, (short) (ISO7816.OFFSET_LC + 1));
            int offset = ISO7816.OFFSET_LC + 3;
            if (lc + offset == command.length) {
                return CASE3_EXTENDED;
            } else if (lc + offset + 2 == command.length) {
                return CASE4_EXTENDED;
            } else {
                throw new IllegalArgumentException("Invalid extended C-APDU: Lc or Le is invalid");
            }
        } else {
            int lc = (command[ISO7816.OFFSET_LC] & 0xFF);
            int offset = ISO7816.OFFSET_LC + 1;
            if (lc + offset == command.length) {
                return CASE3;
            } else if (lc + offset + 1 == command.length) {
                return CASE4;
            } else {
                throw new IllegalArgumentException("Invalid C-APDU: Lc or Le is invalid");
            }
        }
    }

    // Convert the string based protocol into internal protocol byte used by JC
    public static byte getProtocolByte(String protocol) {
        Objects.requireNonNull(protocol, "protocol");
        String p = protocol.toUpperCase(Locale.ENGLISH).replace(" ", "");
        byte protocolByte;

        if (p.equals("T=0") || p.equals("*")) {
            protocolByte = APDU.PROTOCOL_T0;
        } else if (p.equals("T=1")) {
            protocolByte = APDU.PROTOCOL_T1;
        } else if (p.equals("T=CL,TYPE_A,T1") || p.equals("T=CL")) {
            protocolByte = APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A;
            protocolByte |= APDU.PROTOCOL_T1;
        } else if (p.equals("T=CL,TYPE_B,T1")) {
            protocolByte = APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B;
            protocolByte |= APDU.PROTOCOL_T1;
        } else {
            throw new IllegalArgumentException("Unknown protocol: " + protocol);
        }
        return protocolByte;
    }
}
