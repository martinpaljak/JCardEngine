/*
 * Copyright 2011 Licel LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateCrtKey;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;

/**
 * Implementation <code>RSAPrivateCrtKey</code> based on BouncyCastle CryptoAPI.
 *
 * @see RSAPrivateCrtKey
 * @see RSAPrivateCrtKeyParameters
 */
public class RSAPrivateCrtKeyImpl extends RSAKeyImpl implements RSAPrivateCrtKey {
    private static final Logger log = LoggerFactory.getLogger(RSAPrivateCrtKeyImpl.class);
    protected ByteContainer p = new ByteContainer();
    protected ByteContainer q = new ByteContainer();
    protected ByteContainer dp1 = new ByteContainer();
    protected ByteContainer dq1 = new ByteContainer();
    protected ByteContainer pq = new ByteContainer();

    /**
     * Construct not-initialized rsa private crt key
     *
     * @param keySize key size it bits (modulus size)
     * @see KeyBuilder
     */
    public RSAPrivateCrtKeyImpl(short keySize) {
        super(true, keySize);
        type = KeyBuilder.TYPE_RSA_CRT_PRIVATE;
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
    public void setParameters(CipherParameters params) {
        p.setBigInteger(((RSAPrivateCrtKeyParameters) params).getP());
        q.setBigInteger(((RSAPrivateCrtKeyParameters) params).getQ());
        dp1.setBigInteger(((RSAPrivateCrtKeyParameters) params).getDP());
        dq1.setBigInteger(((RSAPrivateCrtKeyParameters) params).getDQ());
        pq.setBigInteger(((RSAPrivateCrtKeyParameters) params).getQInv());
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
        return (p.isInitialized() && q.isInitialized() && dp1.isInitialized() && dq1.isInitialized() && pq.isInitialized());
    }

    public CipherParameters getParameters() {
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
