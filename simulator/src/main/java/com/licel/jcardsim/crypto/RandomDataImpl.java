// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.RandomData;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.bouncycastle.crypto.prng.RandomGenerator;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Implementation <code>RandomData</code> based
 * on BouncyCastle CryptoAPI.
 *
 * @see RandomData
 */
@SuppressWarnings("deprecation")
public class RandomDataImpl extends RandomData {
    byte algorithm;
    // TODO: should settle on just a single one, clarify assumptions on seeding.
    RandomGenerator engine;
    static SecureRandom random;

    static {
        try {
            random = SecureRandom.getInstanceStrong();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("No random?");
        }
    }

    public RandomDataImpl(byte algorithm) {
        this.algorithm = algorithm;
        this.engine = new DigestRandomGenerator(new SHA1Digest());
        this.engine.addSeedMaterial(random.generateSeed(8));
    }

    public void generateData(byte[] buffer, short offset, short length) throws CryptoException {
        engine.nextBytes(buffer, offset, length);
    }

    public void setSeed(byte[] buffer, short offset, short length) {
        // XXX: for ALG_PRESEEDED_DRBG seeding should set known state ?
        engine.addSeedMaterial(Arrays.copyOfRange(buffer, offset, offset + length));
    }

    public byte getAlgorithm() {
        return algorithm;
    }

    public short nextBytes(byte[] buffer, short offset, short length) throws CryptoException {
        engine.nextBytes(buffer, offset, length);
        return (short) (offset + length);
    }
}
