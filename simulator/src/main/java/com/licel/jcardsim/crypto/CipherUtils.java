// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.SEEDEngine;

final class CipherUtils {

    private CipherUtils() {
    }

    enum CipherState {
        UNINITIALIZED,
        INITIALIZED,
        FINALIZED;

        // FINALIZED counts as initialized: the cipher was init'd, then ran to completion.
        boolean initialized() {
            return this != UNINITIALIZED;
        }
    }

    // type is the persistent KeyBuilder.TYPE_* constant
    static BlockCipher of(byte type, short size) {
        if (type == KeyBuilder.TYPE_DES) {
            if (size == KeyBuilder.LENGTH_DES) {
                return new DESEngine();
            }
            if (size == KeyBuilder.LENGTH_DES3_2KEY || size == KeyBuilder.LENGTH_DES3_3KEY) {
                return new DESedeEngine();
            }
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        if (type == KeyBuilder.TYPE_AES) {
            return AESEngine.newInstance();
        }
        if (type == KeyBuilder.TYPE_KOREAN_SEED) {
            return new SEEDEngine();
        }
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        return null;
    }
}
