// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateCrtKey;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

public final class RSAPrivateCrtKeyImpl extends RSAKeyImpl implements RSAPrivateCrtKey {
    private final ByteContainer p;
    private final ByteContainer q;
    private final ByteContainer dp1;
    private final ByteContainer dq1;
    private final ByteContainer pq;

    public RSAPrivateCrtKeyImpl(short keySize, byte memoryType) {
        super(KeyBuilder.TYPE_RSA_CRT_PRIVATE, keySize, memoryType);
        // each CRT prime component is half the modulus size in bytes (bits/8/2 = bits/16)
        short half = (short) (keySize / 16);
        p = new ByteContainer(memoryType, half);
        q = new ByteContainer(memoryType, half);
        dp1 = new ByteContainer(memoryType, half);
        dq1 = new ByteContainer(memoryType, half);
        pq = new ByteContainer(memoryType, half);
    }

    @Override
    void setParameters(CipherParameters params) {
        var crt = (RSAPrivateCrtKeyParameters) params;
        p.setBigInteger(crt.getP());
        q.setBigInteger(crt.getQ());
        dp1.setBigInteger(crt.getDP());
        dq1.setBigInteger(crt.getDQ());
        pq.setBigInteger(crt.getQInv());
    }

    @Override
    public void setP(byte[] buffer, short offset, short length) throws CryptoException {
        p.setBytes(buffer, offset, length);
    }

    @Override
    public void setQ(byte[] buffer, short offset, short length) throws CryptoException {
        q.setBytes(buffer, offset, length);
    }

    @Override
    public void setDP1(byte[] buffer, short offset, short length) throws CryptoException {
        dp1.setBytes(buffer, offset, length);
    }

    @Override
    public void setDQ1(byte[] buffer, short offset, short length) throws CryptoException {
        dq1.setBytes(buffer, offset, length);
    }

    @Override
    public void setPQ(byte[] buffer, short offset, short length) throws CryptoException {
        pq.setBytes(buffer, offset, length);
    }

    @Override
    public short getP(byte[] buffer, short offset) {
        return p.getBytes(buffer, offset);
    }

    @Override
    public short getQ(byte[] buffer, short offset) {
        return q.getBytes(buffer, offset);
    }

    @Override
    public short getDP1(byte[] buffer, short offset) {
        return dp1.getBytes(buffer, offset);
    }

    @Override
    public short getDQ1(byte[] buffer, short offset) {
        return dq1.getBytes(buffer, offset);
    }

    @Override
    public short getPQ(byte[] buffer, short offset) {
        return pq.getBytes(buffer, offset);
    }

    @Override
    public void clearKey() {
        p.clear();
        q.clear();
        dp1.clear();
        dq1.clear();
        pq.clear();
        super.clearKey();
    }

    @Override
    public boolean isInitialized() {
        return p.isInitialized() && q.isInitialized() && dp1.isInitialized() && dq1.isInitialized() && pq.isInitialized();
    }

    @Override
    CipherParameters getParameters() {
        if (!isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        // modulus = p * q;
        // NOTE: prior to BC 1.77 the exponent based Lenstra's check was not done.
        // See https://github.com/bcgit/bc-java/issues/2104
        // Since BC 1.83 the property can be used to disable it. Simulator static init has:
        // System.setProperty("org.bouncycastle.rsa.no_lenstra_check", "true");
        return new RSAPrivateCrtKeyParameters(p.getBigInteger().multiply(q.getBigInteger()), null, null, p.getBigInteger(),
            q.getBigInteger(), dp1.getBigInteger(), dq1.getBigInteger(), pq.getBigInteger());
    }
}
