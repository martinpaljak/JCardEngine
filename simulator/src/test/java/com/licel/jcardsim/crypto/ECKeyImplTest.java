// SPDX-FileCopyrightText: 2013 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.framework.JCSystem;
import javacard.security.KeyBuilder;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

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

}
