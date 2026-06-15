// SPDX-FileCopyrightText: 2013 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.framework.JCSystem;
import javacard.security.KeyBuilder;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

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
        assertInstanceOf(ECCurve.F2m.class, result.getDomainParameters().getCurve());
        instance = new ECPublicKeyImpl(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_192, JCSystem.MEMORY_TYPE_PERSISTENT);
        result = (ECKeyGenerationParameters) instance.getKeyGenerationParameters(rnd);
        assertInstanceOf(ECCurve.Fp.class, result.getDomainParameters().getCurve());
        //private
        instance = new ECPrivateKeyImpl(KeyBuilder.TYPE_EC_F2M_PRIVATE, KeyBuilder.LENGTH_EC_F2M_193, JCSystem.MEMORY_TYPE_PERSISTENT);
        result = (ECKeyGenerationParameters) instance.getKeyGenerationParameters(rnd);
        assertInstanceOf(ECCurve.F2m.class, result.getDomainParameters().getCurve());
        instance = new ECPrivateKeyImpl(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_192, JCSystem.MEMORY_TYPE_PERSISTENT);
        result = (ECKeyGenerationParameters) instance.getKeyGenerationParameters(rnd);
        assertInstanceOf(ECCurve.Fp.class, result.getDomainParameters().getCurve());
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
    }

    private void checkFieldLength(short lengthBits, int fieldBytes) {
        ECKeyImpl key = new ECPublicKeyImpl(KeyBuilder.TYPE_EC_FP_PUBLIC, lengthBits, JCSystem.MEMORY_TYPE_PERSISTENT);
        byte[] buf = new byte[fieldBytes];
        assertEquals(fieldBytes, key.getA(buf, (short) 0));
        assertEquals(fieldBytes, key.getB(buf, (short) 0));
        assertEquals(fieldBytes, key.getField(buf, (short) 0));
    }

    /**
     * A shared-domain private scalar reads back verbatim, not padded to the order length.
     */
    @Test
    public void testSharedPrivateScalarVerbatim() {
        ECKeyImpl domain = new ECPublicKeyImpl(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, JCSystem.MEMORY_TYPE_PERSISTENT);
        ECPrivateKeySharedImpl key = new ECPrivateKeySharedImpl(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256,
                JCSystem.MEMORY_TYPE_PERSISTENT, domain);
        // a tiny scalar reads back at its own one-byte length, not the 32-byte secp256r1 order
        key.setParameters(new ECPrivateKeyParameters(BigInteger.valueOf(0x42), domain.getDomainParameters()));
        byte[] buf = new byte[32];
        assertEquals(1, key.getS(buf, (short) 0));
    }

}
