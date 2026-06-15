// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.base.Simulator;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.crypto.Cipher;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.DSAExt;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.SignerWithRecovery;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.*;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.function.Supplier;

/*
 * Implementation <code>Signature</code> with asymmetric keys based
 * on BouncyCastle CryptoAPI.
 * @see Signature
 */
public final class AsymmetricSignatureImpl extends Signature implements SignatureMessageRecovery {

    // Controls how getLength() computes the maximum signature size.
    private enum LengthRule {
        RSA_MODULUS, // key size in bytes
        ECDSA_DER    // DER SEQUENCE holding two order-sized INTEGERs
    }

    // algByte 0 is the sentinel for entries with no named ALG_* constant (raw ECDSA).
    private enum SigAlg {
        RSA_SHA_ISO9796(ALG_RSA_SHA_ISO9796, MessageDigest.ALG_SHA, Signature.SIG_CIPHER_RSA, Cipher.PAD_ISO9796,
                () -> new ISO9796d2Signer(new RSAEngine(), new SHA1Digest()), null, LengthRule.RSA_MODULUS),
        RSA_RIPEMD160_ISO9796(ALG_RSA_RIPEMD160_ISO9796, MessageDigest.ALG_RIPEMD160, Signature.SIG_CIPHER_RSA, Cipher.PAD_ISO9796,
                () -> new ISO9796d2Signer(new RSAEngine(), new RIPEMD160Digest()), null, LengthRule.RSA_MODULUS),

        RSA_SHA_PKCS1(ALG_RSA_SHA_PKCS1, MessageDigest.ALG_SHA, Signature.SIG_CIPHER_RSA, Cipher.PAD_PKCS1,
                () -> new RSADigestSigner(new SHA1Digest()), new RSAPKCS1Precomputed(X509ObjectIdentifiers.id_SHA1), LengthRule.RSA_MODULUS),
        RSA_SHA_224_PKCS1(ALG_RSA_SHA_224_PKCS1, MessageDigest.ALG_SHA_224, Signature.SIG_CIPHER_RSA, Cipher.PAD_PKCS1,
                () -> new RSADigestSigner(new SHA224Digest()), new RSAPKCS1Precomputed(NISTObjectIdentifiers.id_sha224), LengthRule.RSA_MODULUS),
        RSA_SHA_256_PKCS1(ALG_RSA_SHA_256_PKCS1, MessageDigest.ALG_SHA_256, Signature.SIG_CIPHER_RSA, Cipher.PAD_PKCS1,
                () -> new RSADigestSigner(new SHA256Digest()), new RSAPKCS1Precomputed(NISTObjectIdentifiers.id_sha256), LengthRule.RSA_MODULUS),
        RSA_SHA_384_PKCS1(ALG_RSA_SHA_384_PKCS1, MessageDigest.ALG_SHA_384, Signature.SIG_CIPHER_RSA, Cipher.PAD_PKCS1,
                () -> new RSADigestSigner(new SHA384Digest()), new RSAPKCS1Precomputed(NISTObjectIdentifiers.id_sha384), LengthRule.RSA_MODULUS),
        RSA_SHA_512_PKCS1(ALG_RSA_SHA_512_PKCS1, MessageDigest.ALG_SHA_512, Signature.SIG_CIPHER_RSA, Cipher.PAD_PKCS1,
                () -> new RSADigestSigner(new SHA512Digest()), new RSAPKCS1Precomputed(NISTObjectIdentifiers.id_sha512), LengthRule.RSA_MODULUS),
        RSA_MD5_PKCS1(ALG_RSA_MD5_PKCS1, MessageDigest.ALG_MD5, Signature.SIG_CIPHER_RSA, Cipher.PAD_PKCS1,
                () -> new RSADigestSigner(new MD5Digest()), new RSAPKCS1Precomputed(PKCSObjectIdentifiers.md5), LengthRule.RSA_MODULUS),
        RSA_RIPEMD160_PKCS1(ALG_RSA_RIPEMD160_PKCS1, MessageDigest.ALG_RIPEMD160, Signature.SIG_CIPHER_RSA, Cipher.PAD_PKCS1,
                () -> new RSADigestSigner(new RIPEMD160Digest()), new RSAPKCS1Precomputed(TeleTrusTObjectIdentifiers.ripemd160), LengthRule.RSA_MODULUS),

        RSA_SHA_PKCS1_PSS(ALG_RSA_SHA_PKCS1_PSS, MessageDigest.ALG_SHA, Signature.SIG_CIPHER_RSA, Cipher.PAD_PKCS1_PSS,
                () -> new PSSSigner(new RSAEngine(), new SHA1Digest(), 16), new PSSPrecomputed(SHA1Digest::new, 16), LengthRule.RSA_MODULUS),
        RSA_SHA_224_PKCS1_PSS(ALG_RSA_SHA_224_PKCS1_PSS, MessageDigest.ALG_SHA_224, Signature.SIG_CIPHER_RSA, Cipher.PAD_PKCS1_PSS,
                () -> new PSSSigner(new RSAEngine(), new SHA224Digest(), 28), new PSSPrecomputed(SHA224Digest::new, 28), LengthRule.RSA_MODULUS),
        RSA_SHA_256_PKCS1_PSS(ALG_RSA_SHA_256_PKCS1_PSS, MessageDigest.ALG_SHA_256, Signature.SIG_CIPHER_RSA, Cipher.PAD_PKCS1_PSS,
                () -> new PSSSigner(new RSAEngine(), new SHA256Digest(), 32), new PSSPrecomputed(SHA256Digest::new, 32), LengthRule.RSA_MODULUS),
        RSA_SHA_384_PKCS1_PSS(ALG_RSA_SHA_384_PKCS1_PSS, MessageDigest.ALG_SHA_384, Signature.SIG_CIPHER_RSA, Cipher.PAD_PKCS1_PSS,
                () -> new PSSSigner(new RSAEngine(), new SHA384Digest(), 48), new PSSPrecomputed(SHA384Digest::new, 48), LengthRule.RSA_MODULUS),
        RSA_SHA_512_PKCS1_PSS(ALG_RSA_SHA_512_PKCS1_PSS, MessageDigest.ALG_SHA_512, Signature.SIG_CIPHER_RSA, Cipher.PAD_PKCS1_PSS,
                () -> new PSSSigner(new RSAEngine(), new SHA512Digest(), 64), new PSSPrecomputed(SHA512Digest::new, 64), LengthRule.RSA_MODULUS),
        RSA_MD5_PKCS1_PSS(ALG_RSA_MD5_PKCS1_PSS, MessageDigest.ALG_MD5, Signature.SIG_CIPHER_RSA, Cipher.PAD_PKCS1_PSS,
                () -> new PSSSigner(new RSAEngine(), new MD5Digest(), 16), new PSSPrecomputed(MD5Digest::new, 16), LengthRule.RSA_MODULUS),
        RSA_RIPEMD160_PKCS1_PSS(ALG_RSA_RIPEMD160_PKCS1_PSS, MessageDigest.ALG_RIPEMD160, Signature.SIG_CIPHER_RSA, Cipher.PAD_PKCS1_PSS,
                () -> new PSSSigner(new RSAEngine(), new RIPEMD160Digest(), 20), new PSSPrecomputed(RIPEMD160Digest::new, 20), LengthRule.RSA_MODULUS),

        ECDSA_SHA(ALG_ECDSA_SHA, MessageDigest.ALG_SHA, Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL,
                () -> new DSADigestSigner(new ECDSASigner(), new SHA1Digest()), new ECDSAPrecomputed(ECDSASigner::new), LengthRule.ECDSA_DER),
        ECDSA_SHA_224(ALG_ECDSA_SHA_224, MessageDigest.ALG_SHA_224, Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL,
                () -> new DSADigestSigner(new ECDSASigner(), new SHA224Digest()), new ECDSAPrecomputed(ECDSASigner::new), LengthRule.ECDSA_DER),
        ECDSA_SHA_256(ALG_ECDSA_SHA_256, MessageDigest.ALG_SHA_256, Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL,
                () -> new DSADigestSigner(new ECDSASigner(), new SHA256Digest()), new ECDSAPrecomputed(ECDSASigner::new), LengthRule.ECDSA_DER),
        ECDSA_SHA_384(ALG_ECDSA_SHA_384, MessageDigest.ALG_SHA_384, Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL,
                () -> new DSADigestSigner(new ECDSASigner(), new SHA384Digest()), new ECDSAPrecomputed(ECDSASigner::new), LengthRule.ECDSA_DER),
        ECDSA_SHA_512(ALG_ECDSA_SHA_512, MessageDigest.ALG_SHA_512, Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL,
                () -> new DSADigestSigner(new ECDSASigner(), new SHA512Digest()), new ECDSAPrecomputed(ECDSASigner::new), LengthRule.ECDSA_DER),
        DSA_SHA(ALG_DSA_SHA, MessageDigest.ALG_SHA, Signature.SIG_CIPHER_DSA, Cipher.PAD_NULL,
                () -> new DSADigestSigner(new DSASigner(), new SHA1Digest()), new ECDSAPrecomputed(DSASigner::new), LengthRule.ECDSA_DER),

        ECDSA_RAW((byte) 0, MessageDigest.ALG_NULL, Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL,
                () -> new DSADigestSigner(new ECDSASigner(), new NullDigest()), new ECDSAPrecomputed(ECDSASigner::new), LengthRule.ECDSA_DER);

        final byte algByte;
        final byte md;
        final byte cipher;
        final byte padding;
        final Supplier<Signer> streamingFactory;
        final PrecomputedHashSigner precomputed;
        final LengthRule lengthRule;

        SigAlg(byte algByte, byte md, byte cipher, byte padding, Supplier<Signer> streamingFactory,
                PrecomputedHashSigner precomputed, LengthRule lengthRule) {
            this.algByte = algByte;
            this.md = md;
            this.cipher = cipher;
            this.padding = padding;
            this.streamingFactory = streamingFactory;
            this.precomputed = precomputed;
            this.lengthRule = lengthRule;
        }

        // Resolves a (messageDigest, cipher, padding) triple to a table entry; null when unrecognised.
        static SigAlg from(byte md, byte cipher, byte padding) {
            for (var s : values()) {
                if (s.md == md && s.cipher == cipher && s.padding == padding) {
                    return s;
                }
            }
            return null;
        }

        // Resolves a legacy ALG_* byte; null when unrecognised. algByte 0 is never matched here,
        // so raw ECDSA is reachable only through the triple.
        static SigAlg byByte(byte algorithm) {
            for (var s : values()) {
                if (s.algByte != 0 && s.algByte == algorithm) {
                    return s;
                }
            }
            return null;
        }
    }

    private SigAlg spec;
    Signer engine;
    Key key;
    byte algorithm;
    boolean isInitialized;
    boolean isRecovery;
    byte[] preSig;

    private AsymmetricSignatureImpl(SigAlg spec) {
        this.spec = spec;
        this.algorithm = spec.algByte;
        this.engine = spec.streamingFactory.get();
    }

    // ALG_RSA_SHA_ISO9796_MR has no table entry and is wired up directly here.
    private AsymmetricSignatureImpl() {
        this.algorithm = ALG_RSA_SHA_ISO9796_MR;
        this.isRecovery = true;
        this.engine = new ISO9796d2Signer(new RSAEngine(), new SHA1Digest(), true);
        this.spec = null;
    }

    // Probed by SignatureProxy: an instance for any algorithm this class handles (table entries plus the
    // off-table message-recovery case), else null. The proxy turns a null into NO_SUCH_ALGORITHM.
    public static Signature getInstance(byte algorithm) {
        if (algorithm == ALG_RSA_SHA_ISO9796_MR) {
            return new AsymmetricSignatureImpl();
        }
        SigAlg s = SigAlg.byByte(algorithm);
        return s == null ? null : new AsymmetricSignatureImpl(s);
    }

    public static Signature getInstance(byte messageDigestAlgorithm, byte cipherAlgorithm, byte paddingAlgorithm) {
        SigAlg s = SigAlg.from(messageDigestAlgorithm, cipherAlgorithm, paddingAlgorithm);
        return s == null ? null : new AsymmetricSignatureImpl(s);
    }

    public void init(Key theKey, byte theMode) throws CryptoException {
        if (theKey == null) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (!theKey.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (!(theKey instanceof KeyWithParameters)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }

        if ((engine instanceof ISO9796d2Signer) || (theMode != MODE_SIGN)) {
            KeyWithParameters key = (KeyWithParameters) theKey;
            engine.init(theMode == MODE_SIGN, key.getParameters());
        } else {
            ParametersWithRandom params = new ParametersWithRandom(((KeyWithParameters) theKey).getParameters(),
                    Simulator.current().rng());
            engine.init(theMode == MODE_SIGN, params);
        }
        this.key = theKey;
        isInitialized = true;
    }

    public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen) throws CryptoException {
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    public short getLength() throws CryptoException {
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        if (!key.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (algorithm == ALG_RSA_SHA_ISO9796_MR) {
            return (short) (key.getSize() >> 3);
        }
        return switch (spec.lengthRule) {
            case RSA_MODULUS -> (short) (key.getSize() >> 3);
            case ECDSA_DER -> getECDSASignatureLength();
        };
    }

    private short getECDSASignatureLength() {
        // Maximum DER SEQUENCE { INTEGER r, INTEGER s }: each scalar is order-sized and may carry
        // a 0x00 sign-pad byte, and the SEQUENCE length switches to long form once the content reaches
        // 128 bytes (e.g. 512/521-bit curves), adding one more byte.
        int scalarBytes = (key.getSize() + 7) / 8;
        int element = 2 + (scalarBytes + 1); // 02 || len || (sign pad + magnitude)
        int content = 2 * element; // r and s
        int seqHeader = content < 0x80 ? 2 : 3; // 30 || short- or long-form length
        return (short) (seqHeader + content);
    }

    public byte getAlgorithm() {
        return algorithm;
    }

    public void update(byte[] inBuff, short inOffset, short inLength) throws CryptoException {
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        engine.update(inBuff, inOffset, inLength);
    }

    public short sign(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset)
            throws CryptoException {
        if (isRecovery) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        engine.update(inBuff, inOffset, inLength);
        byte[] sig;
        try {
            sig = engine.generateSignature();
            Util.arrayCopyNonAtomic(sig, (short) 0, sigBuff, sigOffset, (short) sig.length);
            return (short) sig.length;
        } catch (org.bouncycastle.crypto.CryptoException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        } catch (DataLengthException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        } finally {
            engine.reset();
        }
        return -1;
    }

    public boolean verify(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset,
            short sigLength) throws CryptoException {
        if (isRecovery) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        engine.update(inBuff, inOffset, inLength);
        byte[] sig = new byte[sigLength];
        Util.arrayCopyNonAtomic(sigBuff, sigOffset, sig, (short) 0, sigLength);
        boolean b = engine.verifySignature(sig);
        engine.reset();
        return b;
    }

    public short beginVerify(byte[] sigAndRecDataBuff, short buffOffset, short sigLength) throws CryptoException {
        if (!isRecovery) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        preSig = JCSystem.makeTransientByteArray(sigLength, JCSystem.CLEAR_ON_RESET);
        Util.arrayCopyNonAtomic(sigAndRecDataBuff, buffOffset, preSig, (short) 0, sigLength);
        try {
            ((SignerWithRecovery) engine).updateWithRecoveredMessage(preSig);
            return (short) ((SignerWithRecovery) engine).getRecoveredMessage().length;
        } catch (Exception ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        return -1;
    }

    public short sign(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset, short[] recMsgLen,
            short recMsgLenOffset) throws CryptoException {
        if (!isRecovery) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        engine.update(inBuff, inOffset, inLength);
        try {
            byte[] sig = engine.generateSignature();
            Util.arrayCopyNonAtomic(sig, (short) 0, sigBuff, sigOffset, (short) sig.length);
            // generateSignature() sized the recoverable message to exactly the embedded byte count
            recMsgLen[recMsgLenOffset] = (short) ((SignerWithRecovery) engine).getRecoveredMessage().length;
            return (short) sig.length;
        } catch (org.bouncycastle.crypto.CryptoException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        } catch (DataLengthException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        } finally {
            engine.reset();
        }
        return -1;
    }

    public boolean verify(byte[] inBuff, short inOffset, short inLength) throws CryptoException {
        if (!isRecovery) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        if (preSig == null) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        engine.update(inBuff, inOffset, inLength);
        boolean b = engine.verifySignature(preSig);
        engine.reset();
        return b;
    }

    public void setInitialDigest(byte[] bytes, short s, short s1, byte[] bytes1, short s2, short s3)
            throws CryptoException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public short signPreComputedHash(byte[] hashBuff, short hashOffset, short hashLength, byte[] sigBuff,
            short sigOffset) throws CryptoException {
        PrecomputedHashSigner strategy = precomputedStrategy();
        try {
            byte[] sig = strategy.sign(hashBuff, hashOffset, hashLength,
                    ((KeyWithParameters) key).getParameters(), Simulator.current().rng());
            Util.arrayCopyNonAtomic(sig, (short) 0, sigBuff, sigOffset, (short) sig.length);
            return (short) sig.length;
        } catch (org.bouncycastle.crypto.CryptoException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        } catch (DataLengthException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        return 0;
    }

    public boolean verifyPreComputedHash(byte[] hashBuff, short hashOffset, short hashLength, byte[] sigBuff,
            short sigOffset, short sigLength) throws CryptoException {
        PrecomputedHashSigner strategy = precomputedStrategy();
        try {
            return strategy.verify(hashBuff, hashOffset, hashLength, sigBuff, sigOffset, sigLength,
                    ((KeyWithParameters) key).getParameters());
        } catch (org.bouncycastle.crypto.CryptoException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        } catch (DataLengthException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        return false;
    }

    // Returns the precomputed-hash strategy; throws ILLEGAL_USE for ISO9796 and recovery algorithms, which have none.
    private PrecomputedHashSigner precomputedStrategy() {
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        if (spec == null || spec.precomputed == null) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        return spec.precomputed;
    }

    // spec == null means ISO9796_MR, which has no table entry.
    public byte getPaddingAlgorithm() {
        return spec != null ? spec.padding : Cipher.PAD_ISO9796_MR;
    }

    public byte getCipherAlgorithm() {
        return spec != null ? spec.cipher : Signature.SIG_CIPHER_RSA;
    }

    public byte getMessageDigestAlgorithm() {
        return spec != null ? spec.md : MessageDigest.ALG_SHA;
    }

    // Signs and verifies a pre-computed hash without running a streaming digest.
    private interface PrecomputedHashSigner {
        byte[] sign(byte[] hash, int off, int len, CipherParameters key, SecureRandom rng)
                throws org.bouncycastle.crypto.CryptoException;

        boolean verify(byte[] hash, int off, int len, byte[] sig, int sigOff, int sigLen, CipherParameters key)
                throws org.bouncycastle.crypto.CryptoException;
    }

    // Feeds the hash directly to the raw DSA primitive and DER-encodes (r, s), matching DSADigestSigner output.
    private static final class ECDSAPrecomputed implements PrecomputedHashSigner {
        private final Supplier<DSA> dsaFactory;

        ECDSAPrecomputed(Supplier<DSA> dsaFactory) {
            this.dsaFactory = dsaFactory;
        }

        @Override
        public byte[] sign(byte[] hash, int off, int len, CipherParameters key, SecureRandom rng)
                throws org.bouncycastle.crypto.CryptoException {
            DSA dsa = dsaFactory.get();
            dsa.init(true, new ParametersWithRandom(key, rng));
            BigInteger[] rs = dsa.generateSignature(Arrays.copyOfRange(hash, off, off + len));
            try {
                return StandardDSAEncoding.INSTANCE.encode(((DSAExt) dsa).getOrder(), rs[0], rs[1]);
            } catch (IOException e) {
                throw new org.bouncycastle.crypto.CryptoException("ECDSA signature encoding failed", e);
            }
        }

        @Override
        public boolean verify(byte[] hash, int off, int len, byte[] sig, int sigOff, int sigLen, CipherParameters key)
                throws org.bouncycastle.crypto.CryptoException {
            DSA dsa = dsaFactory.get();
            dsa.init(false, key);
            byte[] message = Arrays.copyOfRange(hash, off, off + len);
            byte[] encoded = Arrays.copyOfRange(sig, sigOff, sigOff + sigLen);
            try {
                BigInteger[] rs = StandardDSAEncoding.INSTANCE.decode(((DSAExt) dsa).getOrder(), encoded);
                return dsa.verifySignature(message, rs[0], rs[1]);
            } catch (IOException e) {
                throw new org.bouncycastle.crypto.CryptoException("ECDSA signature decoding failed", e);
            }
        }
    }

    // Wraps the hash in a DigestInfo with the algorithm OID and RSA-encrypts it, matching RSADigestSigner output.
    private static final class RSAPKCS1Precomputed implements PrecomputedHashSigner {
        private final ASN1ObjectIdentifier digestOid;

        RSAPKCS1Precomputed(ASN1ObjectIdentifier digestOid) {
            this.digestOid = digestOid;
        }

        private byte[] digestInfo(byte[] hash, int off, int len) throws org.bouncycastle.crypto.CryptoException {
            byte[] h = Arrays.copyOfRange(hash, off, off + len);
            AlgorithmIdentifier algId = new AlgorithmIdentifier(digestOid, DERNull.INSTANCE);
            try {
                return new DigestInfo(algId, h).getEncoded(ASN1Encoding.DER);
            } catch (IOException e) {
                throw new org.bouncycastle.crypto.CryptoException("DigestInfo encoding failed", e);
            }
        }

        @Override
        public byte[] sign(byte[] hash, int off, int len, CipherParameters key, SecureRandom rng)
                throws org.bouncycastle.crypto.CryptoException {
            AsymmetricBlockCipher rsa = new PKCS1Encoding(new RSABlindedEngine());
            rsa.init(true, key);
            byte[] di = digestInfo(hash, off, len);
            try {
                return rsa.processBlock(di, 0, di.length);
            } catch (InvalidCipherTextException e) {
                throw new org.bouncycastle.crypto.CryptoException("RSA PKCS1 signing failed", e);
            }
        }

        @Override
        public boolean verify(byte[] hash, int off, int len, byte[] sig, int sigOff, int sigLen, CipherParameters key)
                throws org.bouncycastle.crypto.CryptoException {
            AsymmetricBlockCipher rsa = new PKCS1Encoding(new RSABlindedEngine());
            rsa.init(false, key);
            byte[] di = digestInfo(hash, off, len);
            try {
                byte[] block = rsa.processBlock(sig, sigOff, sigLen);
                return Arrays.constantTimeAreEqual(block, di);
            } catch (InvalidCipherTextException e) {
                return false;
            }
        }
    }

    // Passes the hash directly to a raw PSS signer, bypassing the inner digest, matching PSSSigner output for the same salt length.
    private static final class PSSPrecomputed implements PrecomputedHashSigner {
        private final Supplier<Digest> digestFactory;
        private final int saltLen;

        PSSPrecomputed(Supplier<Digest> digestFactory, int saltLen) {
            this.digestFactory = digestFactory;
            this.saltLen = saltLen;
        }

        private PSSSigner rawSigner() {
            return PSSSigner.createRawSigner(new RSAEngine(), digestFactory.get(), digestFactory.get(), saltLen,
                    PSSSigner.TRAILER_IMPLICIT);
        }

        @Override
        public byte[] sign(byte[] hash, int off, int len, CipherParameters key, SecureRandom rng)
                throws org.bouncycastle.crypto.CryptoException {
            PSSSigner pss = rawSigner();
            pss.init(true, new ParametersWithRandom(key, rng));
            pss.update(hash, off, len);
            return pss.generateSignature();
        }

        @Override
        public boolean verify(byte[] hash, int off, int len, byte[] sig, int sigOff, int sigLen, CipherParameters key)
                throws org.bouncycastle.crypto.CryptoException {
            PSSSigner pss = rawSigner();
            pss.init(false, key);
            pss.update(hash, off, len);
            byte[] encoded = new byte[sigLen];
            System.arraycopy(sig, sigOff, encoded, 0, sigLen);
            return pss.verifySignature(encoded);
        }
    }
}
