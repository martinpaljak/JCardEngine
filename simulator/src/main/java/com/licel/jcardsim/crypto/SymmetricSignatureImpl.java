// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.macs.CBCBlockCipherMac;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.List;

/**
 * Implementation
 * <code>Signature</code> with symmetric keys based
 * on BouncyCastle CryptoAPI.
 * @see Signature
 */
public final class SymmetricSignatureImpl extends Signature {
    
    Mac engine;
    MacAlg spec;
    byte algorithm;
    boolean isInitialized;

    // Builds the BouncyCastle MAC around the key's own block cipher. HMAC and retail-MAC (ALG3) rows ignore it:
    // HMAC keys carry no block cipher, and retail MAC always runs over a fresh single-DES engine.
    @FunctionalInterface
    private interface MacBuilder {
        Mac build(byte type, short size);
    }

    // The canonical identity of each MAC is its (messageDigest, cipher, padding) triple; the legacy single-byte
    // ALG_* constant and the key family that init() must match are recorded alongside.
    private enum MacAlg {
        DES_MAC4_NOPAD(ALG_DES_MAC4_NOPAD, MessageDigest.ALG_NULL, SIG_CIPHER_DES_MAC4, Cipher.PAD_NOPAD, SymmetricKeyImpl.KF_DES,
                (t, s) -> new CBCBlockCipherMac(CipherUtils.of(t, s), 32, null)),
        DES_MAC8_NOPAD(ALG_DES_MAC8_NOPAD, MessageDigest.ALG_NULL, SIG_CIPHER_DES_MAC8, Cipher.PAD_NOPAD, SymmetricKeyImpl.KF_DES,
                (t, s) -> new CBCBlockCipherMac(CipherUtils.of(t, s), 64, null)),
        DES_MAC4_ISO9797_M1(ALG_DES_MAC4_ISO9797_M1, MessageDigest.ALG_NULL, SIG_CIPHER_DES_MAC4, Cipher.PAD_ISO9797_M1, SymmetricKeyImpl.KF_DES,
                (t, s) -> new CBCBlockCipherMac(CipherUtils.of(t, s), 32, new ZeroBytePadding())),
        DES_MAC8_ISO9797_M1(ALG_DES_MAC8_ISO9797_M1, MessageDigest.ALG_NULL, SIG_CIPHER_DES_MAC8, Cipher.PAD_ISO9797_M1, SymmetricKeyImpl.KF_DES,
                (t, s) -> new CBCBlockCipherMac(CipherUtils.of(t, s), 64, new ZeroBytePadding())),
        DES_MAC4_ISO9797_M2(ALG_DES_MAC4_ISO9797_M2, MessageDigest.ALG_NULL, SIG_CIPHER_DES_MAC4, Cipher.PAD_ISO9797_M2, SymmetricKeyImpl.KF_DES,
                (t, s) -> new CBCBlockCipherMac(CipherUtils.of(t, s), 32, new ISO7816d4Padding())),
        DES_MAC8_ISO9797_M2(ALG_DES_MAC8_ISO9797_M2, MessageDigest.ALG_NULL, SIG_CIPHER_DES_MAC8, Cipher.PAD_ISO9797_M2, SymmetricKeyImpl.KF_DES,
                (t, s) -> new CBCBlockCipherMac(CipherUtils.of(t, s), 64, new ISO7816d4Padding())),
        DES_MAC4_PKCS5(ALG_DES_MAC4_PKCS5, MessageDigest.ALG_NULL, SIG_CIPHER_DES_MAC4, Cipher.PAD_PKCS5, SymmetricKeyImpl.KF_DES,
                (t, s) -> new CBCBlockCipherMac(CipherUtils.of(t, s), 32, new PKCS7Padding())),
        DES_MAC8_PKCS5(ALG_DES_MAC8_PKCS5, MessageDigest.ALG_NULL, SIG_CIPHER_DES_MAC8, Cipher.PAD_PKCS5, SymmetricKeyImpl.KF_DES,
                (t, s) -> new CBCBlockCipherMac(CipherUtils.of(t, s), 64, new PKCS7Padding())),

        // Retail MAC (ISO 9797-1 algorithm 3): always a fresh single-DES engine, ignores the key cipher.
        DES_MAC4_ISO9797_1_M1_ALG3(ALG_DES_MAC4_ISO9797_1_M1_ALG3, MessageDigest.ALG_NULL, SIG_CIPHER_DES_MAC4, Cipher.PAD_ISO9797_1_M1_ALG3, SymmetricKeyImpl.KF_DES,
                (t, s) -> new ISO9797Alg3Mac(new DESEngine(), 32, new ZeroBytePadding())),
        DES_MAC8_ISO9797_1_M1_ALG3(ALG_DES_MAC8_ISO9797_1_M1_ALG3, MessageDigest.ALG_NULL, SIG_CIPHER_DES_MAC8, Cipher.PAD_ISO9797_1_M1_ALG3, SymmetricKeyImpl.KF_DES,
                (t, s) -> new ISO9797Alg3Mac(new DESEngine(), 64, new ZeroBytePadding())),
        DES_MAC4_ISO9797_1_M2_ALG3(ALG_DES_MAC4_ISO9797_1_M2_ALG3, MessageDigest.ALG_NULL, SIG_CIPHER_DES_MAC4, Cipher.PAD_ISO9797_1_M2_ALG3, SymmetricKeyImpl.KF_DES,
                (t, s) -> new ISO9797Alg3Mac(new DESEngine(), 32, new ISO7816d4Padding())),
        DES_MAC8_ISO9797_1_M2_ALG3(ALG_DES_MAC8_ISO9797_1_M2_ALG3, MessageDigest.ALG_NULL, SIG_CIPHER_DES_MAC8, Cipher.PAD_ISO9797_1_M2_ALG3, SymmetricKeyImpl.KF_DES,
                (t, s) -> new ISO9797Alg3Mac(new DESEngine(), 64, new ISO7816d4Padding())),

        AES_MAC_128_NOPAD(ALG_AES_MAC_128_NOPAD, MessageDigest.ALG_NULL, SIG_CIPHER_AES_MAC128, Cipher.PAD_NOPAD, SymmetricKeyImpl.KF_AES,
                (t, s) -> new CBCBlockCipherMac(CipherUtils.of(t, s), 128, null)),
        AES_CMAC_128(ALG_AES_CMAC_128, MessageDigest.ALG_NULL, SIG_CIPHER_AES_CMAC128, Cipher.PAD_ISO9797_M2, SymmetricKeyImpl.KF_AES,
                (t, s) -> new CMac(CipherUtils.of(t, s), 128)),

        HMAC_SHA1(ALG_HMAC_SHA1, MessageDigest.ALG_SHA, SIG_CIPHER_HMAC, Cipher.PAD_NULL, SymmetricKeyImpl.KF_HMAC,
                (t, s) -> new HMac(new SHA1Digest())),
        HMAC_SHA_256(ALG_HMAC_SHA_256, MessageDigest.ALG_SHA_256, SIG_CIPHER_HMAC, Cipher.PAD_NULL, SymmetricKeyImpl.KF_HMAC,
                (t, s) -> new HMac(new SHA256Digest())),
        HMAC_SHA_384(ALG_HMAC_SHA_384, MessageDigest.ALG_SHA_384, SIG_CIPHER_HMAC, Cipher.PAD_NULL, SymmetricKeyImpl.KF_HMAC,
                (t, s) -> new HMac(new SHA384Digest())),
        HMAC_SHA_512(ALG_HMAC_SHA_512, MessageDigest.ALG_SHA_512, SIG_CIPHER_HMAC, Cipher.PAD_NULL, SymmetricKeyImpl.KF_HMAC,
                (t, s) -> new HMac(new SHA512Digest())),
        HMAC_MD5(ALG_HMAC_MD5, MessageDigest.ALG_MD5, SIG_CIPHER_HMAC, Cipher.PAD_NULL, SymmetricKeyImpl.KF_HMAC,
                (t, s) -> new HMac(new MD5Digest())),
        HMAC_RIPEMD160(ALG_HMAC_RIPEMD160, MessageDigest.ALG_RIPEMD160, SIG_CIPHER_HMAC, Cipher.PAD_NULL, SymmetricKeyImpl.KF_HMAC,
                (t, s) -> new HMac(new RIPEMD160Digest()));

        final byte algByte;
        final byte md;
        final byte cipher;
        final byte padding;
        final List<Byte> family;
        final MacBuilder builder;

        MacAlg(byte algByte, byte md, byte cipher, byte padding, List<Byte> family, MacBuilder builder) {
            this.algByte = algByte;
            this.md = md;
            this.cipher = cipher;
            this.padding = padding;
            this.family = family;
            this.builder = builder;
        }

        // (messageDigest, cipher, padding) -> entry; null when unrecognised.
        static MacAlg from(byte md, byte cipher, byte padding) {
            for (var a : values()) {
                if (a.md == md && a.cipher == cipher && a.padding == padding) {
                    return a;
                }
            }
            return null;
        }

        // Legacy single-byte ALG_* constant -> entry; null when unrecognised.
        static MacAlg byByte(byte algorithm) {
            for (var a : values()) {
                if (a.algByte == algorithm) {
                    return a;
                }
            }
            return null;
        }
    }

    // Engine is not built here: CBC-MAC/CMAC need the key's block cipher, available only in init().
    private SymmetricSignatureImpl(MacAlg spec) {
        this.spec = spec;
        this.algorithm = spec.algByte;
    }

    // Probed by SignatureProxy: an instance for any algorithm this table holds, else null. The proxy is
    // responsible for turning a null into NO_SUCH_ALGORITHM.
    public static Signature getInstance(byte algorithm) {
        var a = MacAlg.byByte(algorithm);
        return a == null ? null : new SymmetricSignatureImpl(a);
    }

    public static Signature getInstance(byte messageDigestAlgorithm, byte cipherAlgorithm, byte paddingAlgorithm) {
        var a = MacAlg.from(messageDigestAlgorithm, cipherAlgorithm, paddingAlgorithm);
        return a == null ? null : new SymmetricSignatureImpl(a);
    }

    @Override
    public void init(Key theKey, byte theMode) throws CryptoException {
        init(theKey, theMode, null, (short) 0, (short) 0);
    }

    @Override
    public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen) throws CryptoException {
        if (theKey == null) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (!theKey.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (!(theKey instanceof SymmetricKeyImpl)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        // JC 3.2 Signature.init: the key family must match the MAC algorithm family.
        if (!spec.family.contains(((SymmetricKeyImpl) theKey).getType())) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        CipherParameters cipherParams;
        if (bArray == null) {
            cipherParams = ((SymmetricKeyImpl) theKey).getParameters();
        } else {
            var probe = CipherUtils.of(theKey.getType(), theKey.getSize());
            if (bLen != probe.getBlockSize()) {
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            }
            cipherParams = new ParametersWithIV(((SymmetricKeyImpl) theKey).getParameters(), bArray, bOff, bLen);
        }
        engine = spec.builder.build(theKey.getType(), theKey.getSize());
        engine.init(cipherParams);
        isInitialized = true;
    }

    @Override
    public short getLength() throws CryptoException {
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        return (short) engine.getMacSize();
    }

    @Override
    public byte getAlgorithm() {
        return algorithm;
    }

    @Override
    public void update(byte[] inBuff, short inOffset, short inLength) throws CryptoException {
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        engine.update(inBuff, inOffset, inLength);
    }

    @Override
    public short sign(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset) throws CryptoException {
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        if ((algorithm == ALG_DES_MAC8_NOPAD || algorithm == ALG_DES_MAC4_NOPAD) && ((inLength % 8) != 0)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        engine.update(inBuff, inOffset, inLength);
        var processedBytes = (short) engine.doFinal(sigBuff, sigOffset);
        engine.reset();
        return processedBytes;
    }

    @Override
    public boolean verify(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset, short sigLength) throws CryptoException {
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        if ((algorithm == ALG_DES_MAC8_NOPAD || algorithm == ALG_DES_MAC4_NOPAD) && ((inLength % 8) != 0)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        engine.update(inBuff, inOffset, inLength);
        var sig = new byte[getLength()];
        engine.doFinal(sig, (short) 0);
        engine.reset();
        if (sigLength != (short) sig.length) {
            return false;
        }
        return Util.arrayCompare(sig, (short) 0, sigBuff, sigOffset, (short) sig.length) == 0;
    }

    @Override
    public void setInitialDigest(byte[] bytes, short s, short s1, byte[] bytes1, short s2, short s3) throws CryptoException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public short signPreComputedHash(byte[] bytes, short s, short s1, byte[] bytes1, short s2) throws CryptoException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean verifyPreComputedHash(byte[] bytes, short s, short s1, byte[] bytes1, short s2, short s3) throws CryptoException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte getPaddingAlgorithm() {
        return spec.padding;
    }

    @Override
    public byte getMessageDigestAlgorithm() {
        return spec.md;
    }

    @Override
    public byte getCipherAlgorithm() {
        return spec.cipher;
    }
}