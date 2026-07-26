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
import java.util.function.BiFunction;
import java.util.function.Supplier;

/**
 * <code>KeyPair</code> backed by the BouncyCastle Crypto API.
 */
public final class KeyPairImpl {

    private enum Alg {
        RSA(KeyPair.ALG_RSA, KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.TYPE_RSA_PRIVATE,
                RSAKeyPairGenerator::new, (len, rnd) -> RSAKeyImpl.getDefaultKeyGenerationParameters(len, rnd)),
        RSA_CRT(KeyPair.ALG_RSA_CRT, KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.TYPE_RSA_CRT_PRIVATE,
                RSAKeyPairGenerator::new, (len, rnd) -> RSAKeyImpl.getDefaultKeyGenerationParameters(len, rnd)),
        EC_FP(KeyPair.ALG_EC_FP, KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.TYPE_EC_FP_PRIVATE,
                ECKeyPairGenerator::new, (len, rnd) -> ECKeyImpl.getDefaultKeyGenerationParameters(KeyPair.ALG_EC_FP, len, rnd)),
        EC_F2M(KeyPair.ALG_EC_F2M, KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.TYPE_EC_F2M_PRIVATE,
                ECKeyPairGenerator::new, (len, rnd) -> ECKeyImpl.getDefaultKeyGenerationParameters(KeyPair.ALG_EC_F2M, len, rnd)),
        DSA(KeyPair.ALG_DSA, KeyBuilder.TYPE_DSA_PUBLIC, KeyBuilder.TYPE_DSA_PRIVATE,
                DSAKeyPairGenerator::new, Alg::dsaParams),
        DH(KeyPair.ALG_DH, KeyBuilder.TYPE_DH_PUBLIC, KeyBuilder.TYPE_DH_PRIVATE,
                DHKeyPairGenerator::new, (len, rnd) -> DHKeyImpl.getDefaultKeyGenerationParameters(len, rnd));

        final byte algByte;
        final byte pubType;
        final byte privType;
        final Supplier<AsymmetricCipherKeyPairGenerator> generator;
        final BiFunction<Short, SecureRandom, KeyGenerationParameters> defaultParams;

        Alg(byte algByte, byte pubType, byte privType, Supplier<AsymmetricCipherKeyPairGenerator> generator,
                BiFunction<Short, SecureRandom, KeyGenerationParameters> defaultParams) {
            this.algByte = algByte;
            this.pubType = pubType;
            this.privType = privType;
            this.generator = generator;
            this.defaultParams = defaultParams;
        }

        private static KeyGenerationParameters dsaParams(Short len, SecureRandom rnd) {
            // DSA key length must be 512..1024 in steps of 64.
            if (len < 512 || len > 1024 || len % 64 != 0) {
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            }
            return DSAKeyImpl.getDefaultKeyGenerationParameters(len, rnd);
        }

        static Alg byByte(byte algorithm) {
            for (var a : values()) {
                if (a.algByte == algorithm) {
                    return a;
                }
            }
            return null;
        }

        static Alg byKeyType(byte keyType) {
            return switch (keyType) {
                case KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.TYPE_RSA_PUBLIC -> RSA;
                case KeyBuilder.TYPE_RSA_CRT_PRIVATE -> RSA_CRT;
                case KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.TYPE_EC_FP_PRIVATE -> EC_FP;
                case KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.TYPE_EC_F2M_PRIVATE -> EC_F2M;
                case KeyBuilder.TYPE_DSA_PUBLIC, KeyBuilder.TYPE_DSA_PRIVATE -> DSA;
                case KeyBuilder.TYPE_DH_PUBLIC, KeyBuilder.TYPE_DH_PRIVATE -> DH;
                default -> null;
            };
        }
    }

    private byte algorithm;
    private short keyLength;
    private AsymmetricCipherKeyPairGenerator engine;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private KeyGenerationParameters keyGenerationParameters;

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
        var a = Alg.byKeyType(keyType);
        if (a == null) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        algorithm = a.algByte;
    }

    private void initEngine() {
        // GH #20: per-card RNG resolved at use, never cached
        SecureRandom rnd = Simulator.current().rng();
        // only public key params carry generation parameters
        if (publicKey != null) {
            keyGenerationParameters = ((KeyWithParameters) publicKey).getKeyGenerationParameters(rnd);
        }
        // Both constructors resolve the algorithm, so it is known good here.
        var a = Alg.byByte(algorithm);
        if (keyGenerationParameters == null) {
            keyGenerationParameters = a.defaultParams.apply(keyLength, rnd);
        }
        engine = a.generator.get();
        engine.init(keyGenerationParameters);
    }

    private void createKeys() {
        var a = Alg.byByte(algorithm);
        if (a == null) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        if (publicKey != null && keyLength == 0) {
            keyLength = publicKey.getSize();
        }
        if (publicKey == null) {
            publicKey = (PublicKey) KeyBuilder.buildKey(a.pubType, keyLength, false);
        }
        if (privateKey == null) {
            privateKey = (PrivateKey) KeyBuilder.buildKey(a.privType, keyLength, false);
        }
    }
}
