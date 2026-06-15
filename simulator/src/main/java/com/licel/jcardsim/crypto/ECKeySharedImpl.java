// SPDX-FileCopyrightText: 2025 dishmaker
// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.ECKey;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;

import java.security.SecureRandom;

public abstract class ECKeySharedImpl extends KeyWithParameters implements ECKey {

    final ECKeyImpl sharedDomain;

    public ECKeySharedImpl(byte keyType, short keySize, byte memoryType, ECKeyImpl sharedDomain) {
        super(keyType, keySize, memoryType);
        this.sharedDomain = sharedDomain;
    }

    @Override
    public void clearKey() {
        // shared domain is referenced by sibling keys; clearing it here would corrupt them, so clear only own S/W
    }

    protected boolean isDomainParametersInitialized() {
        return sharedDomain.isDomainParametersInitialized();
    }

    @Override
    public void setFieldFP(byte[] buffer, short offset, short length) throws CryptoException {
        sharedDomain.setFieldFP(buffer, offset, length);
    }

    @Override
    public void setFieldF2M(short e) throws CryptoException {
        setFieldF2M(e, (short) 0, (short) 0);
    }

    @Override
    public void setFieldF2M(short e1, short e2, short e3) throws CryptoException {
        sharedDomain.setFieldF2M(e1, e2, e3);
    }

    @Override
    public void setA(byte[] buffer, short offset, short length) throws CryptoException {
        sharedDomain.setA(buffer, offset, length);
    }

    @Override
    public void setB(byte[] buffer, short offset, short length) throws CryptoException {
        sharedDomain.setB(buffer, offset, length);
    }

    @Override
    public void setG(byte[] buffer, short offset, short length) throws CryptoException {
        sharedDomain.setG(buffer, offset, length);
    }

    @Override
    public void setR(byte[] buffer, short offset, short length) throws CryptoException {
        sharedDomain.setR(buffer, offset, length);
    }

    @Override
    public void setK(short K) {
        sharedDomain.setK(K);
    }

    @Override
    public short getField(byte[] buffer, short offset) throws CryptoException {
        return sharedDomain.getField(buffer, offset);
    }

    @Override
    public short getA(byte[] buffer, short offset) throws CryptoException {
        return sharedDomain.getA(buffer, offset);
    }

    @Override
    public short getB(byte[] buffer, short offset) throws CryptoException {
        return sharedDomain.getB(buffer, offset);
    }

    @Override
    public short getG(byte[] buffer, short offset) throws CryptoException {
        return sharedDomain.getG(buffer, offset);
    }

    @Override
    public short getR(byte[] buffer, short offset) throws CryptoException {
        return sharedDomain.getR(buffer, offset);
    }

    @Override
    public short getK() throws CryptoException {
        return sharedDomain.getK();
    }

    ECDomainParameters getDomainParameters() {
        return sharedDomain.getDomainParameters();
    }

    final void setDomainParameters(ECDomainParameters parameters) {
        sharedDomain.setDomainParameters(parameters);
    }

    @Override
    KeyGenerationParameters getKeyGenerationParameters(SecureRandom rnd) {
        return sharedDomain.getKeyGenerationParameters(rnd);
    }

    @Override
    public void copyDomainParametersFrom(ECKey eckey) throws CryptoException {
        sharedDomain.copyDomainParametersFrom(eckey);
    }
}
