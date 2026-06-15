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

    static BlockCipher of(byte type, short size) {
        if (SymmetricKeyImpl.KF_DES.contains(type)) {
            if (size == KeyBuilder.LENGTH_DES) {
                return new DESEngine();
            }
            if (size == KeyBuilder.LENGTH_DES3_2KEY || size == KeyBuilder.LENGTH_DES3_3KEY) {
                return new DESedeEngine();
            }
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        if (SymmetricKeyImpl.KF_AES.contains(type)) {
            return AESEngine.newInstance();
        }
        if (SymmetricKeyImpl.KF_SEED.contains(type)) {
            return new SEEDEngine();
        }
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        return null;
    }
}
