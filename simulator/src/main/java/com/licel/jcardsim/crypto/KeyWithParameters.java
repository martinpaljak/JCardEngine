// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
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
