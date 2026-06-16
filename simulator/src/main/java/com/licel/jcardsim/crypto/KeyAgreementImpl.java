// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.DHPrivateKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.PrivateKey;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.function.Supplier;

/**
 * Implementation <code>KeyAgreement</code> based
 * on BouncyCastle CryptoAPI.
 * @see KeyAgreement
 * @see ECDHBasicAgreement
 * @see ECDHCBasicAgreement
 */
public final class KeyAgreementImpl extends KeyAgreement {

    private enum Family {
        EC,
        DH
    }

    // ALG_EC_SVDP_DH_KDF and ALG_EC_SVDP_DHC_KDF alias bytes 1 and 2.
    private enum KaAlg {
        EC_SVDP_DH(ALG_EC_SVDP_DH, Family.EC, ECDHBasicAgreement::new, true, true),
        EC_SVDP_DHC(ALG_EC_SVDP_DHC, Family.EC, ECDHCBasicAgreement::new, true, true),
        EC_SVDP_DH_PLAIN(ALG_EC_SVDP_DH_PLAIN, Family.EC, ECDHBasicAgreement::new, true, false),
        EC_SVDP_DHC_PLAIN(ALG_EC_SVDP_DHC_PLAIN, Family.EC, ECDHCBasicAgreement::new, true, false),
        EC_PACE_GM(ALG_EC_PACE_GM, Family.EC, ECGMAgreement::new, false, false),
        EC_SVDP_DH_PLAIN_XY(ALG_EC_SVDP_DH_PLAIN_XY, Family.EC, ECDHFullAgreement::new, false, false),
        DH_PLAIN(ALG_DH_PLAIN, Family.DH, DHBasicAgreement::new, false, false);

        final byte algByte;
        final Family family;
        final Supplier<BasicAgreement> agreementFactory;
        final boolean truncateToField;
        final boolean hash;

        KaAlg(byte algByte, Family family, Supplier<BasicAgreement> agreementFactory, boolean truncateToField, boolean hash) {
            this.algByte = algByte;
            this.family = family;
            this.agreementFactory = agreementFactory;
            this.truncateToField = truncateToField;
            this.hash = hash;
        }

        static KaAlg byByte(byte algorithm) {
            for (var s : values()) {
                if (s.algByte == algorithm) {
                    return s;
                }
            }
            return null;
        }
    }

    private final KaAlg spec;
    private final BasicAgreement engine;
    private PrivateKey privateKey;

    // Returns null for unknown algorithms; KeyAgreementProxy maps null to NO_SUCH_ALGORITHM.
    public static KeyAgreement getInstance(byte algorithm) {
        var s = KaAlg.byByte(algorithm);
        return s == null ? null : new KeyAgreementImpl(s);
    }

    private KeyAgreementImpl(KaAlg spec) {
        this.spec = spec;
        this.engine = spec.agreementFactory.get();
    }

    @Override
    public void init(PrivateKey privateKey) throws CryptoException {
        if (privateKey == null) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        boolean keyMatches = spec.family == Family.DH ? privateKey instanceof DHPrivateKey : privateKey instanceof ECPrivateKey;
        if (!keyMatches) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        engine.init(((KeyWithParameters) privateKey).getParameters());
        this.privateKey = privateKey;
    }

    @Override
    public byte getAlgorithm() {
        return spec.algByte;
    }

    @Override
    public short generateSecret(byte[] publicData,
            short publicOffset,
            short publicLength,
            byte[] secret,
            short secretOffset) throws CryptoException {
        if (spec.family == Family.DH) {
            return generateDH(publicData, publicOffset, publicLength, secret, secretOffset);
        }
        return generateEC(publicData, publicOffset, publicLength, secret, secretOffset);
    }

    private short generateDH(byte[] publicData, short publicOffset, short publicLength, byte[] secret, short secretOffset) {
        BigInteger pubKey = new BigInteger(1, publicData, publicOffset, publicLength);
        DHParameters baseParam = ((DHKeyParameters) ((KeyWithParameters) privateKey).getParameters()).getParameters();
        BigInteger retAgreement = engine.calculateAgreement(new DHPublicKeyParameters(pubKey, baseParam));
        // the shared secret is padded to the prime length, not trimmed
        var primeBytes = (baseParam.getP().bitLength() + 7) / 8;
        var out = new ByteContainer(JCSystem.MEMORY_TYPE_PERSISTENT, primeBytes);
        out.setBigInteger(retAgreement);
        return out.getBytes(secret, secretOffset);
    }

    private short generateEC(byte[] publicData, short publicOffset, short publicLength, byte[] secret, short secretOffset) {
        byte[] publicKey = new byte[publicLength];
        Util.arrayCopyNonAtomic(publicData, publicOffset, publicKey, (short) 0, publicLength);
        ECDomainParameters dp = ((ECPrivateKeyParameters) ((KeyWithParameters) privateKey).getParameters()).getParameters();
        ECPublicKeyParameters ecp = new ECPublicKeyParameters(dp.getCurve().decodePoint(publicKey), dp);
        byte[] num = engine.calculateAgreement(ecp).toByteArray();

        byte[] result;
        if (spec.truncateToField) {
            // truncate/zero-pad to field size:
            int fieldSize = dp.getCurve().getFieldSize();
            result = new byte[(fieldSize + 7) / 8];
            int numBytes = Math.min(num.length, result.length);
            Util.arrayCopyNonAtomic(
                    num,    (short)(   num.length - numBytes),
                    result, (short)(result.length - numBytes),
                    (short)numBytes);
            Util.arrayFillNonAtomic(result, (short)0, (short)(result.length - numBytes), (byte)0);
        } else {
            // keep the whole result:
            result = num;
        }

        if (spec.hash) {
            // hash the shared secret with SHA-1
            byte[] hashResult = new byte[20];
            var digest = new SHA1Digest();
            digest.update(result, 0, result.length);
            digest.doFinal(hashResult, 0);
            Util.arrayCopyNonAtomic(hashResult, (short) 0, secret, secretOffset, (short) hashResult.length);
            return (short) hashResult.length;
        }
        Util.arrayCopyNonAtomic(result, (short) 0, secret, secretOffset, (short) result.length);
        return (short) result.length;
    }

    /**
     * BouncyCastle doesn't offer ECDH Agreement that provides both coordinates.
     * This is needed for <code>ALG_EC_SVDP_DH_PLAIN_XY</code>.
     * So do it here instead and squeeze the resulting point through byte encoding
     * in a BigInteger.
     */
    private static final class ECDHFullAgreement implements BasicAgreement {
        private ECPrivateKeyParameters key;

        @Override
        public void init(CipherParameters privateKey) {
            this.key = (ECPrivateKeyParameters)privateKey;
        }

        @Override
        public int getFieldSize() {
            return (this.key.getParameters().getCurve().getFieldSize() + 7) / 8;
        }

        @Override
        public BigInteger calculateAgreement(CipherParameters publicKey) {
            ECPublicKeyParameters pub = (ECPublicKeyParameters)publicKey;
            ECPoint result = pub.getQ().multiply(this.key.getD());
            return new BigInteger(1, result.getEncoded(false));
        }
    }

    /**
     * BouncyCastle doesn't offer KeyAgreement analogous to <code>ALG_EC_PACE_GM</code>.
     * So do it here instead and squeeze the resulting point through byte encoding
     * in a BigInteger.
     */
    private static final class ECGMAgreement implements BasicAgreement {
        private ECPrivateKeyParameters key;

        @Override
        public void init(CipherParameters privateKey) {
            this.key = (ECPrivateKeyParameters) privateKey;
        }

        @Override
        public int getFieldSize() {
            return (this.key.getParameters().getCurve().getFieldSize() + 7) / 8;
        }

        @Override
        public BigInteger calculateAgreement(CipherParameters publicKey) {
            ECPublicKeyParameters pub = (ECPublicKeyParameters) publicKey;
            ECPoint result = this.key.getParameters().getG().multiply(this.key.getD()).add(pub.getQ());
            return new BigInteger(1, result.getEncoded(false));
        }
    }
}
