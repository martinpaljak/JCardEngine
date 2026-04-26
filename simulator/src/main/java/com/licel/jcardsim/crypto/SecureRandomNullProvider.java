// SPDX-FileCopyrightText: 2020 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.bouncycastle.crypto.prng.RandomGenerator;

import java.security.SecureRandom;
import java.security.SecureRandomSpi;
// TODO: remove
class SecureRandomNullProvider extends SecureRandom {

    public SecureRandomNullProvider() {
        super(new SecureRandomSpi() {
            RandomGenerator engine = new DigestRandomGenerator(new SHA1Digest());
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
        }, null);
    }
}
