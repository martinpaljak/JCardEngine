// SPDX-FileCopyrightText: 2015 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.proxy.javacard.security;

import com.licel.jcardsim.crypto.CRC16;
import com.licel.jcardsim.crypto.CRC32;
import javacard.security.Checksum;
import javacard.security.CryptoException;

public final class ChecksumProxy {

    public static Checksum getInstance(byte algorithm, boolean externalAccess) throws CryptoException {
        if (externalAccess) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        switch (algorithm) {
            case Checksum.ALG_ISO3309_CRC16:
                return new CRC16();
            case Checksum.ALG_ISO3309_CRC32:
                return new CRC32();
            default:
                CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
                return null;
        }
    }
}
