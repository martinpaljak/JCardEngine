// SPDX-FileCopyrightText: 2015 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.proxy.javacard.security;

import com.licel.jcardsim.crypto.*;
import javacard.security.CryptoException;
import javacard.security.Key;

import static javacard.security.KeyBuilder.*;

public class KeyBuilderProxy {

    public static Key buildKey(byte algorithmicKeyType, byte keyMemoryType, short keyLength, boolean keyEncryption) throws CryptoException {
        if (keyEncryption) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        switch (algorithmicKeyType) {
            case ALG_TYPE_DES:
                requireLength(keyLength, (short) 64, (short) 128, (short) 192);
                return new SymmetricKeyImpl(TYPE_DES, keyLength, keyMemoryType);
            case ALG_TYPE_AES:
                requireLength(keyLength, (short) 128, (short) 192, (short) 256);
                return new SymmetricKeyImpl(TYPE_AES, keyLength, keyMemoryType);
            case ALG_TYPE_KOREAN_SEED:
                requireLength(keyLength, LENGTH_KOREAN_SEED_128);
                return new SymmetricKeyImpl(TYPE_KOREAN_SEED, keyLength, keyMemoryType);
            case ALG_TYPE_HMAC:
                return new SymmetricKeyImpl(TYPE_HMAC, keyLength, keyMemoryType);
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
        var family = KeyFamily.byType(keyType);
        if (family == null) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        return buildKey(family.algType(), family.memoryType(keyType), keyLength, keyEncryption);
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

    private static void requireLength(short keyLength, short... allowed) {
        for (short candidate : allowed) {
            if (keyLength == candidate) {
                return;
            }
        }
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    }

}
