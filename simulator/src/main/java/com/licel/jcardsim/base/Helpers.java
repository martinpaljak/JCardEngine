// SPDX-FileCopyrightText: 2025 Martin Paljak
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

public class Helpers {
    // Utility method to create realistic installation parameters with instance AID, privileges and application parameters
    public static byte[] install_parameters(byte[] aid, byte[] privileges, byte[] params) {
        if (params == null) {
            params = new byte[0];
        }
        if (privileges == null) {
            privileges = new byte[1];
        }

        byte[] data = new byte[1 + aid.length + 1 + privileges.length + 1 + params.length];
        int offset = 0;

        data[offset++] = (byte) aid.length;
        System.arraycopy(aid, 0, data, offset, aid.length);
        offset += aid.length;

        data[offset++] = (byte) privileges.length;
        System.arraycopy(privileges, 0, data, offset, privileges.length);
        offset += privileges.length;

        data[offset++] = (byte) params.length;
        System.arraycopy(params, 0, data, offset, params.length);
        return data;
    }
}
