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
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;

/**
 * Implementation <code>RSAPrivateCrtKey</code> based
 * on BouncyCastle CryptoAPI.
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
     * Construct and initialize rsa key with RSAPrivateCrtKeyParameters.
     * Use in KeyPairImpl
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
        return (p.isInitialized() && q.isInitialized()
                && dp1.isInitialized() && dq1.isInitialized()
                && pq.isInitialized());
    }

    public CipherParameters getParameters() {
        if (!isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        // modulus = p * q;
        // FIXME: prior to BC 1.77 the exponent based Lenstra's check was not done.
        // See https://github.com/bcgit/bc-java/issues/2104
        BigInteger exp = exponent.isInitialized() ? exponent.getBigInteger() : reconstructPublicExponent(p.getBigInteger(), q.getBigInteger(), dp1.getBigInteger(), dq1.getBigInteger(), pq.getBigInteger());

        return new RSAPrivateCrtKeyParameters(p.getBigInteger().multiply(q.getBigInteger()), exp,
                null, p.getBigInteger(), q.getBigInteger(),
                dp1.getBigInteger(), dq1.getBigInteger(), pq.getBigInteger());
    }

    public BigInteger reconstructPublicExponent(BigInteger p, BigInteger q,
                                                BigInteger dp1, BigInteger dq1,
                                                BigInteger pq) {

        BigInteger p1 = p.subtract(BigInteger.ONE);
        BigInteger q1 = q.subtract(BigInteger.ONE);
        BigInteger phi = p1.multiply(q1);

        // First check common public exponents
        BigInteger[] commonExponents = new BigInteger[]{
                BigInteger.valueOf(65537),
                BigInteger.valueOf(17),
                BigInteger.valueOf(3),
                BigInteger.valueOf(5),
                BigInteger.valueOf(257),
                BigInteger.valueOf(65539)
        };

        for (BigInteger candidateE : commonExponents) {
            if (candidateE.gcd(phi).equals(BigInteger.ONE)) {
                BigInteger candidateD = candidateE.modInverse(phi);
                if (candidateD.mod(p1).equals(dp1) && candidateD.mod(q1).equals(dq1)) {
                    return candidateE; // quick match found
                }
            }
        }

        // Perform generalized CRT as fallback
        BigInteger d = robustCRT(dp1, p1, dq1, q1);

        if (!d.gcd(phi).equals(BigInteger.ONE)) {
            throw new ArithmeticException("Reconstructed d is not invertible modulo phi(n). Check CRT inputs.");
        }

        return d.modInverse(phi);
    }

    private BigInteger robustCRT(BigInteger a1, BigInteger m1,
                                 BigInteger a2, BigInteger m2) {
        BigInteger gcd = m1.gcd(m2);
        if (!a1.subtract(a2).mod(gcd).equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("Incompatible CRT inputs");
        }

        BigInteger lcm = m1.divide(gcd).multiply(m2);

        // Extended Euclidean Algorithm to get coefficients
        BigInteger[] euclid = extendedGCD(m1.divide(gcd), m2.divide(gcd));
        BigInteger m1Inv = euclid[1];

        BigInteger diff = a2.subtract(a1).divide(gcd);

        BigInteger result = a1.add(m1.multiply(m1Inv).multiply(diff));

        return result.mod(lcm);
    }

    private BigInteger[] extendedGCD(BigInteger a, BigInteger b) {
        BigInteger old_r = a, r = b;
        BigInteger old_s = BigInteger.ONE, s = BigInteger.ZERO;
        BigInteger old_t = BigInteger.ZERO, t = BigInteger.ONE;

        while (!r.equals(BigInteger.ZERO)) {
            BigInteger quotient = old_r.divide(r);

            BigInteger temp = r;
            r = old_r.subtract(quotient.multiply(r));
            old_r = temp;

            temp = s;
            s = old_s.subtract(quotient.multiply(s));
            old_s = temp;

            temp = t;
            t = old_t.subtract(quotient.multiply(t));
            old_t = temp;
        }

        return new BigInteger[]{old_r, old_s, old_t};
    }

}
