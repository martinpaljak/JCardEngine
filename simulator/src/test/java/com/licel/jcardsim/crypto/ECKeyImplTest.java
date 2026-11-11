// SPDX-FileCopyrightText: 2013 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.testng.annotations.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.testng.Assert.*;

/**
 * Test for <code>ECKeyImplTest</code>.
 */
public class ECKeyImplTest extends SimulatorCoreTest {

    /**
     * Test of getKeyGenerationParameters method, of class ECKeyImpl.
     */
    @Test
    public void testGetKeyGenerationParameters() {
        System.out.println("getKeyGenerationParameters");
        SecureRandom rnd = new SecureRandom();
        // public
        ECKeyImpl instance = new ECPublicKeyImpl(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, JCSystem.MEMORY_TYPE_PERSISTENT);
        ECKeyGenerationParameters result = (ECKeyGenerationParameters) instance.getKeyGenerationParameters(rnd);
        assertTrue(result.getDomainParameters().getCurve() instanceof ECCurve.F2m);
        instance = new ECPublicKeyImpl(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_192, JCSystem.MEMORY_TYPE_PERSISTENT);
        result = (ECKeyGenerationParameters) instance.getKeyGenerationParameters(rnd);
        assertTrue(result.getDomainParameters().getCurve() instanceof ECCurve.Fp);
        //private
        instance = new ECPrivateKeyImpl(KeyBuilder.TYPE_EC_F2M_PRIVATE, KeyBuilder.LENGTH_EC_F2M_193, JCSystem.MEMORY_TYPE_PERSISTENT);
        result = (ECKeyGenerationParameters) instance.getKeyGenerationParameters(rnd);
        assertTrue(result.getDomainParameters().getCurve() instanceof ECCurve.F2m);
        instance = new ECPrivateKeyImpl(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_192, JCSystem.MEMORY_TYPE_PERSISTENT);
        result = (ECKeyGenerationParameters) instance.getKeyGenerationParameters(rnd);
        assertTrue(result.getDomainParameters().getCurve() instanceof ECCurve.Fp);
    }

    /**
     * Domain parameters read back at the full field length regardless of leading zeros.
     */
    @Test
    public void testDomainParameterFieldLength() {
        // secp521r1 b has a zero high byte; it MUST still report 66 bytes (issue #24)
        checkFieldLength(KeyBuilder.LENGTH_EC_FP_521, 66);
        // a = p-3 has its high bit set on these curves; it MUST NOT gain a sign byte
        checkFieldLength(KeyBuilder.LENGTH_EC_FP_256, 32);
        checkFieldLength(KeyBuilder.LENGTH_EC_FP_384, 48);
        // 521 bits round up to 66 bytes, 163 bits to 21
        checkFieldLength(KeyBuilder.LENGTH_EC_FP_521, 66);
        var f2m = new KeyPair(KeyPair.ALG_EC_F2M, KeyBuilder.LENGTH_EC_F2M_163);
        f2m.genKeyPair();
        assertEquals(((ECPublicKey) f2m.getPublic()).getW(new byte[43], (short) 0), 43);
        assertEquals(((ECPrivateKey) f2m.getPrivate()).getA(new byte[21], (short) 0), 21);
        // JC 3.2 ECKey.setG makes the compressed form optional
        var key = new ECPublicKeyImpl(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, JCSystem.MEMORY_TYPE_PERSISTENT);
        var compressed = new byte[33];
        compressed[0] = 0x02;
        assertEquals(expectThrows(CryptoException.class, () -> key.setW(compressed, (short) 0, (short) 33)).getReason(), CryptoException.ILLEGAL_VALUE);
        assertEquals(expectThrows(CryptoException.class, () -> key.setG(compressed, (short) 0, (short) 33)).getReason(), CryptoException.ILLEGAL_VALUE);
    }

    private void checkFieldLength(short lengthBits, int fieldBytes) {
        ECKeyImpl key = new ECPublicKeyImpl(KeyBuilder.TYPE_EC_FP_PUBLIC, lengthBits, JCSystem.MEMORY_TYPE_PERSISTENT);
        byte[] buf = new byte[fieldBytes];
        assertEquals(key.getA(buf, (short) 0), fieldBytes);
        assertEquals(key.getB(buf, (short) 0), fieldBytes);
        assertEquals(key.getField(buf, (short) 0), fieldBytes);
    }

    /**
     * A shared-domain private scalar reads back verbatim, not padded to the order length.
     */
    @Test
    public void testSharedPrivateScalarVerbatim() {
        ECKeyImpl domain = new ECPublicKeyImpl(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, JCSystem.MEMORY_TYPE_PERSISTENT);
        ECPrivateKeyImpl key = new ECPrivateKeyImpl(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256,
                JCSystem.MEMORY_TYPE_PERSISTENT, domain);
        // a tiny scalar reads back at its own one-byte length, not the 32-byte secp256r1 order
        key.setParameters(new ECPrivateKeyParameters(BigInteger.valueOf(0x42), domain.getDomainParameters()));
        byte[] buf = new byte[32];
        assertEquals(key.getS(buf, (short) 0), 1);
    }

}
