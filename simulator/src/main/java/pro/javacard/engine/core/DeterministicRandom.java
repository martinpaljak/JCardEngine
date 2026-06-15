// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.core;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.bouncycastle.crypto.prng.RandomGenerator;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;

// A SecureRandom whose stream is fully reproducible from a seed, so it drops into
// ParametersWithRandom and KeyPair generation for deterministic test reproduction.
public final class DeterministicRandom extends SecureRandom {

    public DeterministicRandom(long seed) {
        super(new Spi(), null);
        var seedbytes = ByteBuffer.allocate(Long.BYTES).putLong(seed).array();
        setSeed(seedbytes);
    }

    private static final class Spi extends SecureRandomSpi {
        final RandomGenerator engine = new DigestRandomGenerator(new SHA1Digest());

        @Override
        protected void engineSetSeed(byte[] arg) {
            engine.addSeedMaterial(arg);
        }

        @Override
        protected void engineNextBytes(byte[] arg) {
            engine.nextBytes(arg);
        }

        @Override
        protected byte[] engineGenerateSeed(int len) {
            byte[] buf = new byte[len];
            engine.nextBytes(buf);
            return buf;
        }
    }
}
