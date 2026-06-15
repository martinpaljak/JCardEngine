// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateCrtKey;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation <code>RSAPrivateCrtKey</code> based on BouncyCastle CryptoAPI.
 *
 * @see RSAPrivateCrtKey
 * @see RSAPrivateCrtKeyParameters
 */
public class RSAPrivateCrtKeyImpl extends RSAKeyImpl implements RSAPrivateCrtKey {
    private static final Logger log = LoggerFactory.getLogger(RSAPrivateCrtKeyImpl.class);
    protected final ByteContainer p;
    protected final ByteContainer q;
    protected final ByteContainer dp1;
    protected final ByteContainer dq1;
    protected final ByteContainer pq;

    /**
     * Construct not-initialized rsa private crt key
     *
     * @param keySize key size it bits (modulus size)
     * @see KeyBuilder
     */
    public RSAPrivateCrtKeyImpl(short keySize) {
        super(true, keySize);
        type = KeyBuilder.TYPE_RSA_CRT_PRIVATE;
        // each CRT prime component is half the modulus size in bytes (bits/8/2 = bits/16)
        short half = (short) (keySize / 16);
        p = new ByteContainer(JCSystem.MEMORY_TYPE_PERSISTENT, half);
        q = new ByteContainer(JCSystem.MEMORY_TYPE_PERSISTENT, half);
        dp1 = new ByteContainer(JCSystem.MEMORY_TYPE_PERSISTENT, half);
        dq1 = new ByteContainer(JCSystem.MEMORY_TYPE_PERSISTENT, half);
        pq = new ByteContainer(JCSystem.MEMORY_TYPE_PERSISTENT, half);
    }

    /**
     * Construct and initialize rsa key with RSAPrivateCrtKeyParameters. Use in KeyPairImpl
     *
     * @param params key params from BouncyCastle API
     * @see javacard.security.KeyPair
     * @see RSAPrivateCrtKeyParameters
     */
    //public RSAPrivateCrtKeyImpl(RSAPrivateCrtKeyParameters params) {
    //    super(new RSAKeyParameters(true, params.getModulus(), params.getExponent()));
    //    type = KeyBuilder.TYPE_RSA_CRT_PRIVATE;
    //    setParameters(params);
    //}
    @Override
    void setParameters(CipherParameters params) {
        RSAPrivateCrtKeyParameters crt = (RSAPrivateCrtKeyParameters) params;
        p.setBigInteger(crt.getP());
        q.setBigInteger(crt.getQ());
        dp1.setBigInteger(crt.getDP());
        dq1.setBigInteger(crt.getDQ());
        pq.setBigInteger(crt.getQInv());
    }

    public void setP(byte[] buffer, short offset, short length) throws CryptoException {
        p.setBytes(buffer, offset, length);
    }

    public void setQ(byte[] buffer, short offset, short length) throws CryptoException {
        q.setBytes(buffer, offset, length);
    }

    public void setDP1(byte[] buffer, short offset, short length) throws CryptoException {
        dp1.setBytes(buffer, offset, length);
    }

    public void setDQ1(byte[] buffer, short offset, short length) throws CryptoException {
        dq1.setBytes(buffer, offset, length);
    }

    public void setPQ(byte[] buffer, short offset, short length) throws CryptoException {
        pq.setBytes(buffer, offset, length);
    }

    public short getP(byte[] buffer, short offset) {
        return p.getBytes(buffer, offset);
    }

    public short getQ(byte[] buffer, short offset) {
        return q.getBytes(buffer, offset);
    }

    public short getDP1(byte[] buffer, short offset) {
        return dp1.getBytes(buffer, offset);
    }

    public short getDQ1(byte[] buffer, short offset) {
        return dq1.getBytes(buffer, offset);
    }

    public short getPQ(byte[] buffer, short offset) {
        return pq.getBytes(buffer, offset);
    }

    public void clearKey() {
        super.clearKey();
        p.clear();
        q.clear();
        dp1.clear();
        dq1.clear();
        pq.clear();
    }

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
