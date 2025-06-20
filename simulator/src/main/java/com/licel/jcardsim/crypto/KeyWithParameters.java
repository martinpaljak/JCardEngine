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

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.SecureRandom;

/**
 * KeyWithParameters.
 */
interface KeyWithParameters {

    /**
     * Get cipher key parameters for use with BouncyCastle Crypto API
     *
     * @return key parameters
     */
    CipherParameters getParameters();

    /**
     * Get keypair generation parameters for use with BouncyCastle Crypto API
     *
     * @param rnd Secure Random Generator
     * @return key parameters
     */
    KeyGenerationParameters getKeyGenerationParameters(SecureRandom rnd);

    /**
     * Set cipher key for use with BouncyCastle Crypto API
     *
     * @param params key parameters
     */
    void setParameters(CipherParameters params);
}
