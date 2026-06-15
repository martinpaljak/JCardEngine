// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;

import java.security.SecureRandom;

public abstract class ECKeyImpl extends KeyWithParameters implements ECKey {

    final ECDomain domain;
    private final boolean ownsDomain;

    public ECKeyImpl(byte keyType, short keySize, byte memoryType) {
        super(keyType, keySize, memoryType);
        this.domain = new ECDomain(keyType, keySize, memoryType);
        this.ownsDomain = true;
    }

    public ECKeyImpl(byte keyType, short keySize, byte memoryType, ECKeyImpl shared) {
        super(keyType, keySize, memoryType);
        // borrows domain from sibling; domain parameters set on any peer are visible to all
        this.domain = shared.domain;
        this.ownsDomain = false;
    }

    @Override
    public void clearKey() {
        // borrowed domain is still in use by sibling keys; only the owner clears it
        if (ownsDomain) {
            domain.clear();
        }
    }

    protected boolean isDomainParametersInitialized() {
        return domain.isInitialized();
    }

    @Override
    public void setFieldFP(byte[] buffer, short offset, short length) throws CryptoException {
        domain.setFieldFP(buffer, offset, length);
    }

    @Override
    public void setFieldF2M(short e) throws CryptoException {
        domain.setFieldF2M(e, (short) 0, (short) 0);
    }

    @Override
    public void setFieldF2M(short e1, short e2, short e3) throws CryptoException {
        domain.setFieldF2M(e1, e2, e3);
    }

    @Override
    public void setA(byte[] buffer, short offset, short length) throws CryptoException {
        domain.setA(buffer, offset, length);
    }

    @Override
    public void setB(byte[] buffer, short offset, short length) throws CryptoException {
        domain.setB(buffer, offset, length);
    }

    @Override
    public void setG(byte[] buffer, short offset, short length) throws CryptoException {
        domain.setG(buffer, offset, length);
    }

    @Override
    public void setR(byte[] buffer, short offset, short length) throws CryptoException {
        domain.setR(buffer, offset, length);
    }

    @Override
    public void setK(short K) {
        domain.setK(K);
    }

    @Override
    public short getField(byte[] buffer, short offset) throws CryptoException {
        return domain.getField(buffer, offset);
    }

    @Override
    public short getA(byte[] buffer, short offset) throws CryptoException {
        return domain.getA(buffer, offset);
    }

    @Override
    public short getB(byte[] buffer, short offset) throws CryptoException {
        return domain.getB(buffer, offset);
    }

    @Override
    public short getG(byte[] buffer, short offset) throws CryptoException {
        return domain.getG(buffer, offset);
    }

    @Override
    public short getR(byte[] buffer, short offset) throws CryptoException {
        return domain.getR(buffer, offset);
    }

    @Override
    public short getK() throws CryptoException {
        return domain.getK();
    }

    ECDomainParameters getDomainParameters() {
        return domain.getDomainParameters();
    }

    @Override
    KeyGenerationParameters getKeyGenerationParameters(SecureRandom rnd) {
        if (domain.isInitialized()) {
            return new ECKeyGenerationParameters(domain.getDomainParameters(), rnd);
        }
        return new ECKeyGenerationParameters(ECDomain.getDefaultsDomainParameters(type, size), rnd);
    }

    static KeyGenerationParameters getDefaultKeyGenerationParameters(byte algorithm, short keySize, SecureRandom rnd) {
        byte keyType = algorithm == KeyPair.ALG_EC_FP ? KeyBuilder.TYPE_EC_FP_PUBLIC : KeyBuilder.TYPE_EC_F2M_PUBLIC;
        return new ECKeyGenerationParameters(ECDomain.getDefaultsDomainParameters(keyType, keySize), rnd);
    }

    @Override
    public void copyDomainParametersFrom(ECKey eckey) throws CryptoException {
        // ECKey interface exposes no getter for the F2M field, so the source must be an ECKeyImpl.
        ECKeyImpl src = unwrap(eckey);
        if (src == null) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            return;
        }
        if (!src.domain.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        domain.copyFrom(src.domain);
    }

    private static ECKeyImpl unwrap(ECKey key) {
        if (key instanceof ECKeyImpl impl) {
            return impl;
        }
        return null;
    }
}
