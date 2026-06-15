// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.base.Simulator;
import javacard.security.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;

import java.security.SecureRandom;

/**
 * <code>KeyPair</code> backed by the BouncyCastle Crypto API.
 *
 * @see KeyPair
 */
public final class KeyPairImpl {

    byte algorithm;
    short keyLength;
    AsymmetricCipherKeyPairGenerator engine;
    PrivateKey privateKey;
    PublicKey publicKey;
    KeyGenerationParameters keyGenerationParameters;

    public void genKeyPair() throws CryptoException {
        initEngine();
        createKeys();
        AsymmetricCipherKeyPair kp = engine.generateKeyPair();
        ((KeyWithParameters) publicKey).setParameters(kp.getPublic());
        ((KeyWithParameters) privateKey).setParameters(kp.getPrivate());
    }

    public KeyPairImpl(byte algorithm, short keyLength) throws CryptoException {
        this.algorithm = algorithm;
        this.keyLength = keyLength;
        createKeys();
    }

    public KeyPairImpl(PublicKey publicKey, PrivateKey privateKey)
            throws CryptoException {
        if (publicKey == null && privateKey == null) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        if ((publicKey != null) && !(publicKey instanceof KeyWithParameters)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        this.publicKey = publicKey;
        if (this.publicKey != null) {
            selectAlgorithmByType(this.publicKey.getType());
        }
        if ((privateKey != null) && !(privateKey instanceof KeyWithParameters)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        this.privateKey = privateKey;
        if (this.privateKey != null) {
            selectAlgorithmByType(this.privateKey.getType());
        }
    }

    public PublicKey getPublic() {
        return publicKey;
    }

    public PrivateKey getPrivate() {
        return privateKey;
    }

    private void selectAlgorithmByType(byte keyType) {
        switch (keyType) {
            case KeyBuilder.TYPE_RSA_PRIVATE:
            case KeyBuilder.TYPE_RSA_PUBLIC:
                algorithm = KeyPair.ALG_RSA;
                break;
            case KeyBuilder.TYPE_RSA_CRT_PRIVATE:
                algorithm = KeyPair.ALG_RSA_CRT;
                break;
            case KeyBuilder.TYPE_EC_F2M_PUBLIC:
            case KeyBuilder.TYPE_EC_F2M_PRIVATE:
                algorithm = KeyPair.ALG_EC_F2M;
                break;
            case KeyBuilder.TYPE_EC_FP_PUBLIC:
            case KeyBuilder.TYPE_EC_FP_PRIVATE:
                algorithm = KeyPair.ALG_EC_FP;
                break;
            case KeyBuilder.TYPE_DSA_PUBLIC:
            case KeyBuilder.TYPE_DSA_PRIVATE:
                algorithm = KeyPair.ALG_DSA;
                break;
            case KeyBuilder.TYPE_DH_PUBLIC:
            case KeyBuilder.TYPE_DH_PRIVATE:
                algorithm = KeyPair.ALG_DH;
                break;
            default:
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
    }

    private void initEngine() {
        // GH #20: per-card RNG resolved at use, never cached
        SecureRandom rnd = Simulator.current().rng();
        // only public key params carry generation parameters
        if (publicKey != null) {
            keyGenerationParameters = ((KeyWithParameters) publicKey).getKeyGenerationParameters(rnd);
        }
        switch (algorithm) {
            case KeyPair.ALG_RSA:
            case KeyPair.ALG_RSA_CRT:
                if (keyGenerationParameters == null) {
                    keyGenerationParameters = RSAKeyImpl.getDefaultKeyGenerationParameters(keyLength, rnd);
                }
                engine = new RSAKeyPairGenerator();
                break;
            case KeyPair.ALG_DSA:
                if (keyLength < 512 || keyLength > 1024 || keyLength % 64 != 0) {
                    CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
                }
                if (keyGenerationParameters == null) {
                    keyGenerationParameters = DSAKeyImpl.getDefaultKeyGenerationParameters(keyLength, rnd);
                }
                engine = new DSAKeyPairGenerator();
                break;
            case KeyPair.ALG_EC_F2M:
            case KeyPair.ALG_EC_FP:
                if (keyGenerationParameters == null) {
                    keyGenerationParameters = ECKeyImpl.getDefaultKeyGenerationParameters(algorithm, keyLength, rnd);
                }
                engine = new ECKeyPairGenerator();
                break;
            case KeyPair.ALG_DH:
                if (keyGenerationParameters == null) {
                    keyGenerationParameters = DHKeyImpl.getDefaultKeyGenerationParameters(keyLength, rnd);
                }
                engine = new DHKeyPairGenerator();
                break;
            default:
                CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
                break;
        }
        engine.init(keyGenerationParameters);
    }

    private void createKeys() {
        byte privateKeyType = 0;
        byte publicKeyType = 0;
        switch (algorithm) {
            case KeyPair.ALG_RSA:
                publicKeyType = KeyBuilder.TYPE_RSA_PUBLIC;
                privateKeyType = KeyBuilder.TYPE_RSA_PRIVATE;
                break;
            case KeyPair.ALG_RSA_CRT:
                publicKeyType = KeyBuilder.TYPE_RSA_PUBLIC;
                privateKeyType = KeyBuilder.TYPE_RSA_CRT_PRIVATE;
                break;
            case KeyPair.ALG_EC_FP:
                publicKeyType = KeyBuilder.TYPE_EC_FP_PUBLIC;
                privateKeyType = KeyBuilder.TYPE_EC_FP_PRIVATE;
                break;
            case KeyPair.ALG_EC_F2M:
                publicKeyType = KeyBuilder.TYPE_EC_F2M_PUBLIC;
                privateKeyType = KeyBuilder.TYPE_EC_F2M_PRIVATE;
                break;
            case KeyPair.ALG_DSA:
                publicKeyType = KeyBuilder.TYPE_DSA_PUBLIC;
                privateKeyType = KeyBuilder.TYPE_DSA_PRIVATE;
                break;
            case KeyPair.ALG_DH:
                publicKeyType = KeyBuilder.TYPE_DH_PUBLIC;
                privateKeyType = KeyBuilder.TYPE_DH_PRIVATE;
                break;
            default:
                CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
                break;
        }
        if (publicKey != null && keyLength == 0) {
            keyLength = publicKey.getSize();
        }
        if (publicKey == null) {
            publicKey = (PublicKey) KeyBuilder.buildKey(publicKeyType, keyLength, false);
        }
        if (privateKey == null) {
            privateKey = (PrivateKey) KeyBuilder.buildKey(privateKeyType, keyLength, false);
        }
    }
}
