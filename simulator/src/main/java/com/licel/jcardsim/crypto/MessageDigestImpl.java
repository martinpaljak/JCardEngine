// SPDX-FileCopyrightText: 2026 Martin Paljak
// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.InitializedMessageDigest;
import javacard.security.MessageDigest;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.util.Pack;

/**
 * {@link MessageDigest} / {@link InitializedMessageDigest} backed by BouncyCastle digests.
 */
public final class MessageDigestImpl extends InitializedMessageDigest {

    private ExtendedDigest engine;        // replaced by setInitialDigest when resuming a hash
    private final byte algorithm;
    private final short blockSize;
    private final short stateSize;        // intermediate-hash state size; 0 = not InitializedMessageDigest-capable

    public MessageDigestImpl(byte algorithm) {
        this.algorithm = algorithm;
        engine = newEngine(algorithm, null);
        blockSize = (short) engine.getByteLength();
        stateSize = intermediateStateSize(algorithm);
    }

    // Fresh digest when encodedState is null, otherwise one restored from a BC-encoded state.
    // Only the SHA family carries the encoded-state constructor; MD5 and RIPEMD160 are normal-digest only.
    private static ExtendedDigest newEngine(byte algorithm, byte[] encodedState) {
        return switch (algorithm) {
            case ALG_SHA -> encodedState == null ? new SHA1Digest() : new SHA1Digest(encodedState);
            case ALG_MD5 -> new MD5Digest();
            case ALG_RIPEMD160 -> new RIPEMD160Digest();
            case ALG_SHA_224 -> encodedState == null ? new SHA224Digest() : new SHA224Digest(encodedState);
            case ALG_SHA_256 -> encodedState == null ? new SHA256Digest() : new SHA256Digest(encodedState);
            case ALG_SHA_384 -> encodedState == null ? new SHA384Digest() : new SHA384Digest(encodedState);
            case ALG_SHA_512 -> encodedState == null ? new SHA512Digest() : new SHA512Digest(encodedState);
            case ALG_SHA3_224 -> encodedState == null ? new SHA3Digest(224) : new SHA3Digest(encodedState);
            case ALG_SHA3_256 -> encodedState == null ? new SHA3Digest(256) : new SHA3Digest(encodedState);
            case ALG_SHA3_384 -> encodedState == null ? new SHA3Digest(384) : new SHA3Digest(encodedState);
            case ALG_SHA3_512 -> encodedState == null ? new SHA3Digest(512) : new SHA3Digest(encodedState);
            default -> {
                CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
                yield null; // unreachable: throwIt always throws
            }
        };
    }

    // JC API MessageDigest intermediate-hash sizes; 0 marks an algorithm that does not support it.
    private static short intermediateStateSize(byte algorithm) {
        return (short) switch (algorithm) {
            case ALG_SHA -> 20;
            case ALG_SHA_224, ALG_SHA_256 -> 32;
            case ALG_SHA_384, ALG_SHA_512 -> 64;
            case ALG_SHA3_224, ALG_SHA3_256, ALG_SHA3_384, ALG_SHA3_512 -> 200; // Keccak-f[1600] state, FIPS 202
            default -> 0; // MD5, RIPEMD160: intermediate hash not supported
        };
    }

    @Override
    public byte getAlgorithm() {
        return algorithm;
    }

    @Override
    public byte getLength() {
        return (byte) engine.getDigestSize();
    }

    @Override
    public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) {
        engine.update(inBuff, inOffset, inLength);
        return (short) engine.doFinal(outBuff, outOffset);
    }

    @Override
    public void update(byte[] inBuff, short inOffset, short inLength) {
        engine.update(inBuff, inOffset, inLength);
    }

    @Override
    public void reset() {
        engine.reset();
    }

    @Override
    public void setInitialDigest(byte[] initialDigestBuf, short initialDigestOffset, short initialDigestLength, byte[] digestedMsgLenBuf, short digestedMsgLenOffset, short digestedMsgLenLength) throws CryptoException {
        if (stateSize == 0) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        if (initialDigestLength != stateSize) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        if (!checkSupportDigestedMsgLenLength(digestedMsgLenLength)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }

        long byteCountLo = 0;
        long byteCountHi = 0;
        for (short i = 0; i < digestedMsgLenLength; i++) {
            if (i < 8) {
                byteCountLo = (byteCountLo << 8) + (digestedMsgLenBuf[digestedMsgLenOffset + i] & 0xff);
            } else {
                byteCountHi = (byteCountHi << 8) + (digestedMsgLenBuf[digestedMsgLenOffset + i] & 0xff);
            }
        }
        if (byteCountLo % blockSize != 0) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }

        // Patch the caller's chaining value and processed-length into a pristine encoded state, then rebuild.
        engine.reset();
        var enc = ((EncodableDigest) engine).getEncodedState();
        System.arraycopy(initialDigestBuf, initialDigestOffset, enc, stateOffset(), stateSize);
        if (!(engine instanceof KeccakDigest)) {
            var countOff = engine instanceof LongDigest ? 12 : 8;
            Pack.longToBigEndian(byteCountLo, enc, countOff);
            if (engine instanceof LongDigest) {
                Pack.longToBigEndian(byteCountHi, enc, countOff + 8);
            }
        }
        engine = newEngine(algorithm, enc);
    }

    private boolean checkSupportDigestedMsgLenLength(short digestedMsgLenLength) {
        if (digestedMsgLenLength == 0) {
            return false;
        }
        if (engine instanceof KeccakDigest) {
            return true; // SHA-3 sponge carries no message-length padding
        }
        return digestedMsgLenLength <= (blockSize == 128 ? 16 : 8);
    }

    void getIntermediateDigest(byte[] intermediateDigest, int off) {
        var enc = ((EncodableDigest) engine).getEncodedState();
        System.arraycopy(enc, stateOffset(), intermediateDigest, off, stateSize);
    }

    // Where the chaining value (or Keccak state) sits inside BC's getEncodedState().
    private int stateOffset() {
        if (engine instanceof KeccakDigest) {
            return 1;  // after the purpose byte
        }
        if (engine instanceof LongDigest) {
            return 28; // after xBuf, xBufOff, byteCount1, byteCount2 (SHA-384/512)
        }
        return 16;     // after xBuf, xBufOff, byteCount (SHA-1, SHA-224, SHA-256)
    }

    short getBlockSize() {
        return blockSize;
    }

    short getIntermediateStateSize() {
        return stateSize;
    }

}
