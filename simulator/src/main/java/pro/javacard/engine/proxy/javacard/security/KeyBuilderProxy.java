// SPDX-FileCopyrightText: 2015 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.proxy.javacard.security;

import com.licel.jcardsim.crypto.*;
import javacard.security.CryptoException;
import javacard.security.Key;

import static javacard.framework.JCSystem.MEMORY_TYPE_PERSISTENT;
import static javacard.framework.JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT;
import static javacard.framework.JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
import static javacard.security.KeyBuilder.*;

public class KeyBuilderProxy {

    public static Key buildKey(byte algorithmicKeyType, byte keyMemoryType, short keyLength, boolean keyEncryption) throws CryptoException {
        if (keyEncryption) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        switch (algorithmicKeyType) {
            case ALG_TYPE_DES:
                requireLength(keyLength, (short) 64, (short) 128, (short) 192);
                return new SymmetricKeyImpl(symType(ALG_TYPE_DES, keyMemoryType), keyLength, keyMemoryType);
            case ALG_TYPE_AES:
                requireLength(keyLength, (short) 128, (short) 192, (short) 256);
                return new SymmetricKeyImpl(symType(ALG_TYPE_AES, keyMemoryType), keyLength, keyMemoryType);
            case ALG_TYPE_KOREAN_SEED:
                requireLength(keyLength, LENGTH_KOREAN_SEED_128);
                return new SymmetricKeyImpl(symType(ALG_TYPE_KOREAN_SEED, keyMemoryType), keyLength, keyMemoryType);
            case ALG_TYPE_HMAC:
                return new SymmetricKeyImpl(symType(ALG_TYPE_HMAC, keyMemoryType), keyLength, keyMemoryType);
            case ALG_TYPE_RSA_PUBLIC:
                return new RSAKeyImpl(TYPE_RSA_PUBLIC, keyLength, keyMemoryType);
            case ALG_TYPE_RSA_PRIVATE:
                return new RSAKeyImpl(TYPE_RSA_PRIVATE, keyLength, keyMemoryType);
            case ALG_TYPE_RSA_CRT_PRIVATE:
                return new RSAPrivateCrtKeyImpl(keyLength, keyMemoryType);
            case ALG_TYPE_DSA_PUBLIC:
                return new DSAPublicKeyImpl(keyLength, keyMemoryType);
            case ALG_TYPE_DSA_PRIVATE:
                return new DSAPrivateKeyImpl(keyLength, keyMemoryType);
            case ALG_TYPE_EC_FP_PUBLIC:
            case ALG_TYPE_EC_FP_PARAMETERS:
                return new ECPublicKeyImpl(TYPE_EC_FP_PUBLIC, keyLength, keyMemoryType);
            case ALG_TYPE_EC_FP_PRIVATE:
                return new ECPrivateKeyImpl(TYPE_EC_FP_PRIVATE, keyLength, keyMemoryType);
            case ALG_TYPE_EC_F2M_PUBLIC:
            case ALG_TYPE_EC_F2M_PARAMETERS:
                return new ECPublicKeyImpl(TYPE_EC_F2M_PUBLIC, keyLength, keyMemoryType);
            case ALG_TYPE_EC_F2M_PRIVATE:
                return new ECPrivateKeyImpl(TYPE_EC_F2M_PRIVATE, keyLength, keyMemoryType);
            case ALG_TYPE_DH_PUBLIC:
                return new DHPublicKeyImpl(keyLength, keyMemoryType);
            case ALG_TYPE_DH_PRIVATE:
                return new DHPrivateKeyImpl(keyLength, keyMemoryType);
            default:
                break;
        }
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        return null;
    }

    public static Key buildKey(byte keyType, short keyLength, boolean keyEncryption) throws CryptoException {
        return switch (keyType) {
            case TYPE_DES -> buildKey(ALG_TYPE_DES, MEMORY_TYPE_PERSISTENT, keyLength, keyEncryption);
            case TYPE_DES_TRANSIENT_RESET -> buildKey(ALG_TYPE_DES, MEMORY_TYPE_TRANSIENT_RESET, keyLength, keyEncryption);
            case TYPE_DES_TRANSIENT_DESELECT -> buildKey(ALG_TYPE_DES, MEMORY_TYPE_TRANSIENT_DESELECT, keyLength, keyEncryption);
            case TYPE_AES -> buildKey(ALG_TYPE_AES, MEMORY_TYPE_PERSISTENT, keyLength, keyEncryption);
            case TYPE_AES_TRANSIENT_RESET -> buildKey(ALG_TYPE_AES, MEMORY_TYPE_TRANSIENT_RESET, keyLength, keyEncryption);
            case TYPE_AES_TRANSIENT_DESELECT -> buildKey(ALG_TYPE_AES, MEMORY_TYPE_TRANSIENT_DESELECT, keyLength, keyEncryption);
            case TYPE_HMAC -> buildKey(ALG_TYPE_HMAC, MEMORY_TYPE_PERSISTENT, keyLength, keyEncryption);
            case TYPE_HMAC_TRANSIENT_RESET -> buildKey(ALG_TYPE_HMAC, MEMORY_TYPE_TRANSIENT_RESET, keyLength, keyEncryption);
            case TYPE_HMAC_TRANSIENT_DESELECT -> buildKey(ALG_TYPE_HMAC, MEMORY_TYPE_TRANSIENT_DESELECT, keyLength, keyEncryption);
            case TYPE_KOREAN_SEED -> buildKey(ALG_TYPE_KOREAN_SEED, MEMORY_TYPE_PERSISTENT, keyLength, keyEncryption);
            case TYPE_KOREAN_SEED_TRANSIENT_RESET -> buildKey(ALG_TYPE_KOREAN_SEED, MEMORY_TYPE_TRANSIENT_RESET, keyLength, keyEncryption);
            case TYPE_KOREAN_SEED_TRANSIENT_DESELECT -> buildKey(ALG_TYPE_KOREAN_SEED, MEMORY_TYPE_TRANSIENT_DESELECT, keyLength, keyEncryption);
            case TYPE_RSA_PUBLIC -> buildKey(ALG_TYPE_RSA_PUBLIC, MEMORY_TYPE_PERSISTENT, keyLength, keyEncryption);
            case TYPE_RSA_PRIVATE -> buildKey(ALG_TYPE_RSA_PRIVATE, MEMORY_TYPE_PERSISTENT, keyLength, keyEncryption);
            case TYPE_RSA_PRIVATE_TRANSIENT_RESET -> buildKey(ALG_TYPE_RSA_PRIVATE, MEMORY_TYPE_TRANSIENT_RESET, keyLength, keyEncryption);
            case TYPE_RSA_PRIVATE_TRANSIENT_DESELECT -> buildKey(ALG_TYPE_RSA_PRIVATE, MEMORY_TYPE_TRANSIENT_DESELECT, keyLength, keyEncryption);
            case TYPE_RSA_CRT_PRIVATE -> buildKey(ALG_TYPE_RSA_CRT_PRIVATE, MEMORY_TYPE_PERSISTENT, keyLength, keyEncryption);
            case TYPE_RSA_CRT_PRIVATE_TRANSIENT_RESET -> buildKey(ALG_TYPE_RSA_CRT_PRIVATE, MEMORY_TYPE_TRANSIENT_RESET, keyLength, keyEncryption);
            case TYPE_RSA_CRT_PRIVATE_TRANSIENT_DESELECT -> buildKey(ALG_TYPE_RSA_CRT_PRIVATE, MEMORY_TYPE_TRANSIENT_DESELECT, keyLength, keyEncryption);
            case TYPE_DSA_PUBLIC -> buildKey(ALG_TYPE_DSA_PUBLIC, MEMORY_TYPE_PERSISTENT, keyLength, keyEncryption);
            case TYPE_DSA_PRIVATE -> buildKey(ALG_TYPE_DSA_PRIVATE, MEMORY_TYPE_PERSISTENT, keyLength, keyEncryption);
            case TYPE_DSA_PRIVATE_TRANSIENT_RESET -> buildKey(ALG_TYPE_DSA_PRIVATE, MEMORY_TYPE_TRANSIENT_RESET, keyLength, keyEncryption);
            case TYPE_DSA_PRIVATE_TRANSIENT_DESELECT -> buildKey(ALG_TYPE_DSA_PRIVATE, MEMORY_TYPE_TRANSIENT_DESELECT, keyLength, keyEncryption);
            case TYPE_EC_F2M_PUBLIC -> buildKey(ALG_TYPE_EC_F2M_PUBLIC, MEMORY_TYPE_PERSISTENT, keyLength, keyEncryption);
            case TYPE_EC_F2M_PRIVATE -> buildKey(ALG_TYPE_EC_F2M_PRIVATE, MEMORY_TYPE_PERSISTENT, keyLength, keyEncryption);
            case TYPE_EC_F2M_PRIVATE_TRANSIENT_RESET -> buildKey(ALG_TYPE_EC_F2M_PRIVATE, MEMORY_TYPE_TRANSIENT_RESET, keyLength, keyEncryption);
            case TYPE_EC_F2M_PRIVATE_TRANSIENT_DESELECT -> buildKey(ALG_TYPE_EC_F2M_PRIVATE, MEMORY_TYPE_TRANSIENT_DESELECT, keyLength, keyEncryption);
            case TYPE_EC_FP_PUBLIC -> buildKey(ALG_TYPE_EC_FP_PUBLIC, MEMORY_TYPE_PERSISTENT, keyLength, keyEncryption);
            case TYPE_EC_FP_PRIVATE -> buildKey(ALG_TYPE_EC_FP_PRIVATE, MEMORY_TYPE_PERSISTENT, keyLength, keyEncryption);
            case TYPE_EC_FP_PRIVATE_TRANSIENT_RESET -> buildKey(ALG_TYPE_EC_FP_PRIVATE, MEMORY_TYPE_TRANSIENT_RESET, keyLength, keyEncryption);
            case TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT -> buildKey(ALG_TYPE_EC_FP_PRIVATE, MEMORY_TYPE_TRANSIENT_DESELECT, keyLength, keyEncryption);
            case TYPE_DH_PUBLIC -> buildKey(ALG_TYPE_DH_PUBLIC, MEMORY_TYPE_PERSISTENT, keyLength, keyEncryption);
            case TYPE_DH_PUBLIC_TRANSIENT_RESET -> buildKey(ALG_TYPE_DH_PUBLIC, MEMORY_TYPE_TRANSIENT_RESET, keyLength, keyEncryption);
            case TYPE_DH_PUBLIC_TRANSIENT_DESELECT -> buildKey(ALG_TYPE_DH_PUBLIC, MEMORY_TYPE_TRANSIENT_DESELECT, keyLength, keyEncryption);
            case TYPE_DH_PRIVATE -> buildKey(ALG_TYPE_DH_PRIVATE, MEMORY_TYPE_PERSISTENT, keyLength, keyEncryption);
            case TYPE_DH_PRIVATE_TRANSIENT_RESET -> buildKey(ALG_TYPE_DH_PRIVATE, MEMORY_TYPE_TRANSIENT_RESET, keyLength, keyEncryption);
            case TYPE_DH_PRIVATE_TRANSIENT_DESELECT -> buildKey(ALG_TYPE_DH_PRIVATE, MEMORY_TYPE_TRANSIENT_DESELECT, keyLength, keyEncryption);
            default -> {
                CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
                yield null;
            }
        };
    }

    public static Key buildKeyWithSharedDomain(byte algorithmicKeyType, byte keyMemoryType, Key domainParameters, boolean keyEncryption) throws CryptoException {
        if (keyEncryption) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        ECKeyImpl domain = (ECKeyImpl) domainParameters;
        switch (algorithmicKeyType) {
            case ALG_TYPE_EC_FP_PRIVATE:
                return new ECPrivateKeyImpl(TYPE_EC_FP_PRIVATE, domain.getSize(), keyMemoryType, domain);
            case ALG_TYPE_EC_FP_PUBLIC:
            case ALG_TYPE_EC_FP_PARAMETERS:
                return new ECPublicKeyImpl(TYPE_EC_FP_PUBLIC, domain.getSize(), keyMemoryType, domain);
            case ALG_TYPE_EC_F2M_PRIVATE:
                return new ECPrivateKeyImpl(TYPE_EC_F2M_PRIVATE, domain.getSize(), keyMemoryType, domain);
            case ALG_TYPE_EC_F2M_PUBLIC:
            case ALG_TYPE_EC_F2M_PARAMETERS:
                return new ECPublicKeyImpl(TYPE_EC_F2M_PUBLIC, domain.getSize(), keyMemoryType, domain);
            default:
                break;
        }
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        return null;
    }

    public static byte getMemoryType(Key key) {
        if (key instanceof KeyWithParameters ours) {
            return ours.getMemoryType();
        }
        // spec gives no error code for non-KeyWithParameters keys; ILLEGAL_VALUE is the closest fit
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        return 0;
    }

    private static byte symType(byte algorithmicKeyType, byte keyMemoryType) {
        return switch (algorithmicKeyType) {
            case ALG_TYPE_DES -> memVariant(keyMemoryType, TYPE_DES, TYPE_DES_TRANSIENT_RESET, TYPE_DES_TRANSIENT_DESELECT);
            case ALG_TYPE_AES -> memVariant(keyMemoryType, TYPE_AES, TYPE_AES_TRANSIENT_RESET, TYPE_AES_TRANSIENT_DESELECT);
            case ALG_TYPE_HMAC -> memVariant(keyMemoryType, TYPE_HMAC, TYPE_HMAC_TRANSIENT_RESET, TYPE_HMAC_TRANSIENT_DESELECT);
            default -> memVariant(keyMemoryType, TYPE_KOREAN_SEED, TYPE_KOREAN_SEED_TRANSIENT_RESET, TYPE_KOREAN_SEED_TRANSIENT_DESELECT);
        };
    }

    private static byte memVariant(byte keyMemoryType, byte persistent, byte reset, byte deselect) {
        if (keyMemoryType == MEMORY_TYPE_TRANSIENT_RESET) {
            return reset;
        }
        if (keyMemoryType == MEMORY_TYPE_TRANSIENT_DESELECT) {
            return deselect;
        }
        return persistent;
    }

    private static void requireLength(short keyLength, short... allowed) {
        for (short candidate : allowed) {
            if (keyLength == candidate) {
                return;
            }
        }
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    }

}
