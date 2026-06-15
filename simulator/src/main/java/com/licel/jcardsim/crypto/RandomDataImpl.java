// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.base.Simulator;
import javacard.security.CryptoException;
import javacard.security.RandomData;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.bouncycastle.crypto.prng.RandomGenerator;

import java.util.Arrays;

public final class RandomDataImpl extends RandomData {
    byte algorithm;
    RandomGenerator engine;

    public RandomDataImpl(byte algorithm) {
        this.algorithm = algorithm;
        this.engine = new DigestRandomGenerator(new SHA1Digest());
        // GH #20: seed from the per-card RNG
        this.engine.addSeedMaterial(Simulator.current().rng().generateSeed(8));
    }

    @Override
    @SuppressWarnings("deprecation") // RandomData.generateData is deprecated in favour of nextBytes, but still abstract
    public void generateData(byte[] buffer, short offset, short length) throws CryptoException {
        engine.nextBytes(buffer, offset, length);
    }

    @Override
    public void setSeed(byte[] buffer, short offset, short length) {
        engine.addSeedMaterial(Arrays.copyOfRange(buffer, offset, offset + length));
    }

    @Override
    public byte getAlgorithm() {
        return algorithm;
    }

    @Override
    public short nextBytes(byte[] buffer, short offset, short length) throws CryptoException {
        engine.nextBytes(buffer, offset, length);
        return (short) (offset + length);
    }
}
