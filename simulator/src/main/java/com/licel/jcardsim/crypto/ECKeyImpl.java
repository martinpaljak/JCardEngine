// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.math.ec.ECCurve;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Set;

public abstract class ECKeyImpl extends KeyWithParameters implements ECKey {

    private static final Set<Integer> F2M_SIZES = Set.of(113, 131, 163, 193, 233, 283, 409, 571);
    private static final Set<Integer> FP_SIZES = Set.of(112, 128, 160, 192, 224, 256, 384, 521);

    private final ByteContainer a;
    private final ByteContainer b;
    private final ByteContainer g;
    private final ByteContainer r;
    private final ByteContainer fp;
    private short k;
    private short e1;
    private short e2;
    private short e3;
    private boolean isKInitialized;

    public ECKeyImpl(byte keyType, short keySize, byte memoryType) {
        super(keyType, keySize, memoryType);

        // field elements occupy the field byte length; the order can be a byte wider than the field
        // (e.g. secp160r1), so r takes the curve's exact order width.
        var fieldBytes = (keySize + 7) / 8;
        a = new ByteContainer(memoryType, fieldBytes);
        b = new ByteContainer(memoryType, fieldBytes);
        g = new ByteContainer(memoryType, 1 + 2 * fieldBytes);
        r = new ByteContainer(memoryType, orderBytes(keyType, keySize));
        fp = new ByteContainer(memoryType, fieldBytes);

        var defaults = getOptionalDomainParameters(type, size);
        if (defaults != null) {
            setDomainParameters(defaults);
        }
    }

    // the order can be a byte wider than the field; fall back to the field width for an
    // applet-defined curve that has no named defaults
    static short orderBytes(byte keyType, short keySize) {
        var defaults = getOptionalDomainParameters(keyType, keySize);
        if (defaults == null) {
            return (short) ((keySize + 7) / 8);
        }
        return (short) ((defaults.getN().bitLength() + 7) / 8);
    }

    @Override
    public void clearKey() {
        a.clear();
        b.clear();
        g.clear();
        r.clear();
        fp.clear();
        k = 0;
        e1 = 0;
        e2 = 0;
        e3 = 0;
    }

    protected boolean isDomainParametersInitialized() {
        return a.isInitialized() && b.isInitialized() && g.isInitialized() && r.isInitialized()
                && isKInitialized && (fp.isInitialized() || k != 0);
    }

    @Override
    public void setFieldFP(byte[] buffer, short offset, short length) throws CryptoException {
        fp.setBytes(buffer, offset, length);
    }

    @Override
    public void setFieldF2M(short e) throws CryptoException {
        setFieldF2M(e, (short) 0, (short) 0);
    }

    @Override
    public void setFieldF2M(short e1, short e2, short e3) throws CryptoException {
        this.e1 = e1;
        this.e2 = e2;
        this.e3 = e3;
    }

    @Override
    public void setA(byte[] buffer, short offset, short length) throws CryptoException {
        a.setBytes(buffer, offset, length);
    }

    @Override
    public void setB(byte[] buffer, short offset, short length) throws CryptoException {
        b.setBytes(buffer, offset, length);
    }

    @Override
    public void setG(byte[] buffer, short offset, short length) throws CryptoException {
        g.setBytes(buffer, offset, length);
    }

    @Override
    public void setR(byte[] buffer, short offset, short length) throws CryptoException {
        r.setBytes(buffer, offset, length);
    }

    @Override
    public void setK(short K) {
        this.k = K;
        isKInitialized = true;
    }

    @Override
    public short getField(byte[] buffer, short offset) throws CryptoException {
        return fp.getBytes(buffer, offset);
    }

    @Override
    public short getA(byte[] buffer, short offset) throws CryptoException {
        return a.getBytes(buffer, offset);
    }

    @Override
    public short getB(byte[] buffer, short offset) throws CryptoException {
        return b.getBytes(buffer, offset);
    }

    @Override
    public short getG(byte[] buffer, short offset) throws CryptoException {
        return g.getBytes(buffer, offset);
    }

    @Override
    public short getR(byte[] buffer, short offset) throws CryptoException {
        return r.getBytes(buffer, offset);
    }

    @Override
    public short getK() throws CryptoException {
        if (!isKInitialized) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        return k;
    }

    ECDomainParameters getDomainParameters() {
        if (!isDomainParametersInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        ECCurve curve = null;
        if (fp.isInitialized()) {
            curve = new ECCurve.Fp(fp.getBigInteger(), a.getBigInteger(), b.getBigInteger(), r.getBigInteger(), BigInteger.valueOf(k));
        } else {
            curve = new ECCurve.F2m(size, e1, e2, e3, a.getBigInteger(), b.getBigInteger(), r.getBigInteger(), BigInteger.valueOf(k));
        }
        return new ECDomainParameters(curve, curve.decodePoint(g.getBytes()), r.getBigInteger(), BigInteger.valueOf(k));
    }

    final void setDomainParameters(ECDomainParameters parameters) {
        a.setBigInteger(parameters.getCurve().getA().toBigInteger());
        b.setBigInteger(parameters.getCurve().getB().toBigInteger());
        // generator: 04 || X || Y, coordinates already padded to the field length by BouncyCastle
        g.setBytes(parameters.getG().getEncoded(false));
        // order
        r.setBigInteger(parameters.getN());
        // cofactor
        setK(parameters.getH().shortValue());
        if (parameters.getCurve() instanceof ECCurve.Fp ecfp) {
            fp.setBigInteger(ecfp.getQ());
        } else {
            ECCurve.F2m ecf2m = (ECCurve.F2m) parameters.getCurve();
            setFieldF2M((short) ecf2m.getK1(), (short) ecf2m.getK2(), (short) ecf2m.getK3());
        }
    }

    @Override
    KeyGenerationParameters getKeyGenerationParameters(SecureRandom rnd) {
        if (isDomainParametersInitialized()) {
            return new ECKeyGenerationParameters(getDomainParameters(), rnd);
        }
        return new ECKeyGenerationParameters(getDefaultsDomainParameters(type, size), rnd);
    }

    static KeyGenerationParameters getDefaultKeyGenerationParameters(byte algorithm, short keySize, SecureRandom rnd) {
        byte keyType = algorithm == KeyPair.ALG_EC_FP ? KeyBuilder.TYPE_EC_FP_PUBLIC : KeyBuilder.TYPE_EC_F2M_PUBLIC;
        return new ECKeyGenerationParameters(getDefaultsDomainParameters(keyType, keySize), rnd);
    }

    static ECDomainParameters getDefaultsDomainParameters(byte keyType, short keySize) {
        var defaults = getOptionalDomainParameters(keyType, keySize);
        if (defaults == null) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        return defaults;
    }

    static ECDomainParameters getOptionalDomainParameters(byte keyType, short keySize) {
        // Curve names follow SECG SEC 2 (http://www.secg.org/sec2-v2.pdf).
        String curveName;
        if (F2M_SIZES.contains((int) keySize)) {
            if (keyType != KeyBuilder.TYPE_EC_F2M_PRIVATE && keyType != KeyBuilder.TYPE_EC_F2M_PUBLIC) {
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            }
            curveName = "sect" + keySize + "r1";
        } else if (FP_SIZES.contains((int) keySize)) {
            if (keyType != KeyBuilder.TYPE_EC_FP_PRIVATE && keyType != KeyBuilder.TYPE_EC_FP_PUBLIC) {
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            }
            curveName = "secp" + keySize + "r1";
        } else {
            return null;
        }
        var x9params = SECNamedCurves.getByName(curveName);
        if (x9params == null) {
            return null;
        }
        return new ECDomainParameters(x9params.getCurve(), x9params.getG(), x9params.getN(), x9params.getH(), x9params.getSeed());
    }

    @Override
    public void copyDomainParametersFrom(ECKey eckey) throws CryptoException {
        // ECKey interface exposes no getter for the F2M field, so the source must be an ECKeyImpl.
        ECKeyImpl src = unwrap(eckey);
        if (src == null) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            return;
        }
        if (!src.isDomainParametersInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (src.fp.isInitialized()) {
            fp.setBytes(src.fp.getBytes());
        } else {
            setFieldF2M(src.e1, src.e2, src.e3);
        }
        a.setBytes(src.a.getBytes());
        b.setBytes(src.b.getBytes());
        g.setBytes(src.g.getBytes());
        r.setBytes(src.r.getBytes());
        setK(src.k);
    }

    private static ECKeyImpl unwrap(ECKey key) {
        if (key instanceof ECKeyImpl impl) {
            return impl;
        }
        if (key instanceof ECKeySharedImpl shared) {
            return shared.sharedDomain;
        }
        return null;
    }
}
