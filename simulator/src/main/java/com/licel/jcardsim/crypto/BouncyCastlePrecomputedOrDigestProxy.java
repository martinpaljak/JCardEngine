// SPDX-FileCopyrightText: 2018 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import org.bouncycastle.crypto.Digest;

public class BouncyCastlePrecomputedOrDigestProxy implements Digest {
    
    private final Digest parentDigest;
    private byte[] precomputedDigestValue = null;

    public BouncyCastlePrecomputedOrDigestProxy(Digest parentDigest) {
        this.parentDigest = parentDigest;
    }

    @Override
    public String getAlgorithmName() {
        return parentDigest.getAlgorithmName();
    }

    @Override
    public int getDigestSize() {
        return parentDigest.getDigestSize();
    }

    @Override
    public void update(byte in) {
        if (precomputedDigestValue == null) {
            parentDigest.update(in);
        }
    }

    @Override
    public void update(byte[] in, int inOff, int len) {
        if (precomputedDigestValue == null) {
            parentDigest.update(in, inOff, len);
        }
    }

    @Override
    public int doFinal(byte[] out, int outOff) {
        if (precomputedDigestValue == null) {
            return parentDigest.doFinal(out, outOff);
        }
        System.arraycopy(precomputedDigestValue, 0, out, outOff, precomputedDigestValue.length);
        int len = precomputedDigestValue.length;
        precomputedDigestValue = null;
        return len;
    }

    public void setPrecomputedValue(byte[] in, int inOff, int inLength) {
        int digestSize = getDigestSize();
        if (inLength!= digestSize) {
            throw new IllegalArgumentException();
        }
        precomputedDigestValue = new byte[digestSize];
        System.arraycopy(in, inOff, precomputedDigestValue, 0, digestSize);
    }

    @Override
    public void reset() {
        precomputedDigestValue = null;
        parentDigest.reset();
    }
}
