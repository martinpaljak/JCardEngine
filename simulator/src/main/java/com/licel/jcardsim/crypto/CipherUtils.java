// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.framework.JCSystem;
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

    // JCSystem memory type backing a KeyBuilder key type: the TRANSIENT variants clear on
    // deselect or reset, everything else persists.
    static byte key2mem(byte keyType) {
        switch (keyType) {
            case KeyBuilder.TYPE_DES_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_AES_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_KOREAN_SEED_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_RSA_PRIVATE_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_RSA_CRT_PRIVATE_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_DSA_PRIVATE_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_EC_F2M_PRIVATE_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_DH_PUBLIC_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_DH_PRIVATE_TRANSIENT_DESELECT:
                return JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT;
            case KeyBuilder.TYPE_DES_TRANSIENT_RESET:
            case KeyBuilder.TYPE_AES_TRANSIENT_RESET:
            case KeyBuilder.TYPE_KOREAN_SEED_TRANSIENT_RESET:
            case KeyBuilder.TYPE_HMAC_TRANSIENT_RESET:
            case KeyBuilder.TYPE_RSA_PRIVATE_TRANSIENT_RESET:
            case KeyBuilder.TYPE_RSA_CRT_PRIVATE_TRANSIENT_RESET:
            case KeyBuilder.TYPE_DSA_PRIVATE_TRANSIENT_RESET:
            case KeyBuilder.TYPE_EC_F2M_PRIVATE_TRANSIENT_RESET:
            case KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET:
            case KeyBuilder.TYPE_DH_PUBLIC_TRANSIENT_RESET:
            case KeyBuilder.TYPE_DH_PRIVATE_TRANSIENT_RESET:
                return JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            default:
                return JCSystem.MEMORY_TYPE_PERSISTENT;
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
