package com.licel.jcardsim.base;

import org.bouncycastle.util.encoders.Hex;

public class Helpers {
    // Utility method to create realistic installation parameters with instance AID, privileges and application parameters
    public static byte[] install_parameters(byte[] aid, byte[] params) {
        if (params == null)
            params = new byte[0];
        byte[] privileges = Hex.decode("00");
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
