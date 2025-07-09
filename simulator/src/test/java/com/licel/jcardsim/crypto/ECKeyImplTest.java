/*
 * Copyright 2013 Licel LLC.
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

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.framework.JCSystem;
import javacard.security.KeyBuilder;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
