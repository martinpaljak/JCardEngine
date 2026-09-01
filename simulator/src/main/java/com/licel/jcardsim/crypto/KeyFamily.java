// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.framework.JCSystem;

import java.util.List;

import static javacard.security.KeyBuilder.*;

/**
 * KeyBuilder TYPE_* constants of one algorithm family, one per memory type.
 * Families without transient variants repeat the persistent constant.
 */
public record KeyFamily(byte algType, byte persistent, byte reset, byte deselect) {

    private static final List<KeyFamily> ALL = List.of(
            new KeyFamily(ALG_TYPE_DES, TYPE_DES, TYPE_DES_TRANSIENT_RESET, TYPE_DES_TRANSIENT_DESELECT),
            new KeyFamily(ALG_TYPE_AES, TYPE_AES, TYPE_AES_TRANSIENT_RESET, TYPE_AES_TRANSIENT_DESELECT),
            new KeyFamily(ALG_TYPE_HMAC, TYPE_HMAC, TYPE_HMAC_TRANSIENT_RESET, TYPE_HMAC_TRANSIENT_DESELECT),
            new KeyFamily(ALG_TYPE_KOREAN_SEED, TYPE_KOREAN_SEED, TYPE_KOREAN_SEED_TRANSIENT_RESET, TYPE_KOREAN_SEED_TRANSIENT_DESELECT),
            new KeyFamily(ALG_TYPE_RSA_PUBLIC, TYPE_RSA_PUBLIC, TYPE_RSA_PUBLIC, TYPE_RSA_PUBLIC),
            new KeyFamily(ALG_TYPE_RSA_PRIVATE, TYPE_RSA_PRIVATE, TYPE_RSA_PRIVATE_TRANSIENT_RESET, TYPE_RSA_PRIVATE_TRANSIENT_DESELECT),
            new KeyFamily(ALG_TYPE_RSA_CRT_PRIVATE, TYPE_RSA_CRT_PRIVATE, TYPE_RSA_CRT_PRIVATE_TRANSIENT_RESET, TYPE_RSA_CRT_PRIVATE_TRANSIENT_DESELECT),
            new KeyFamily(ALG_TYPE_DSA_PUBLIC, TYPE_DSA_PUBLIC, TYPE_DSA_PUBLIC, TYPE_DSA_PUBLIC),
            new KeyFamily(ALG_TYPE_DSA_PRIVATE, TYPE_DSA_PRIVATE, TYPE_DSA_PRIVATE_TRANSIENT_RESET, TYPE_DSA_PRIVATE_TRANSIENT_DESELECT),
            new KeyFamily(ALG_TYPE_EC_F2M_PUBLIC, TYPE_EC_F2M_PUBLIC, TYPE_EC_F2M_PUBLIC, TYPE_EC_F2M_PUBLIC),
            new KeyFamily(ALG_TYPE_EC_F2M_PRIVATE, TYPE_EC_F2M_PRIVATE, TYPE_EC_F2M_PRIVATE_TRANSIENT_RESET, TYPE_EC_F2M_PRIVATE_TRANSIENT_DESELECT),
            new KeyFamily(ALG_TYPE_EC_FP_PUBLIC, TYPE_EC_FP_PUBLIC, TYPE_EC_FP_PUBLIC, TYPE_EC_FP_PUBLIC),
            new KeyFamily(ALG_TYPE_EC_FP_PRIVATE, TYPE_EC_FP_PRIVATE, TYPE_EC_FP_PRIVATE_TRANSIENT_RESET, TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT),
            new KeyFamily(ALG_TYPE_DH_PUBLIC, TYPE_DH_PUBLIC, TYPE_DH_PUBLIC_TRANSIENT_RESET, TYPE_DH_PUBLIC_TRANSIENT_DESELECT),
            new KeyFamily(ALG_TYPE_DH_PRIVATE, TYPE_DH_PRIVATE, TYPE_DH_PRIVATE_TRANSIENT_RESET, TYPE_DH_PRIVATE_TRANSIENT_DESELECT));

    // family of a TYPE_* constant, null if unknown
    public static KeyFamily byType(byte type) {
        for (KeyFamily f : ALL) {
            if (f.persistent == type || f.reset == type || f.deselect == type) {
                return f;
            }
        }
        return null;
    }

    // TYPE_* constant for the given memory type
    public byte type(byte memoryType) {
        if (memoryType == JCSystem.MEMORY_TYPE_TRANSIENT_RESET) {
            return reset;
        }
        if (memoryType == JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT) {
            return deselect;
        }
        return persistent;
    }

    // MEMORY_TYPE_* implied by a TYPE_* constant
    public byte memoryType(byte type) {
        if (type == persistent) {
            return JCSystem.MEMORY_TYPE_PERSISTENT;
        }
        return type == reset ? JCSystem.MEMORY_TYPE_TRANSIENT_RESET : JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT;
    }
}
