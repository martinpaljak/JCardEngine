// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.crypto.CipherUtils.CipherState;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DefaultBufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.function.Supplier;

/**
 * Implementation <code>Cipher</code> with symmetric keys based
 * on BouncyCastle CryptoAPI.
 *
 * @see Cipher
 */
public final class SymmetricCipherImpl extends Cipher {

    // Wraps the key's raw block cipher into the chaining mode.
    private enum Mode {
        ECB {
            @Override BlockCipher wrap(BlockCipher cipher) {
                return cipher;
            }
        },
        CBC {
            @Override BlockCipher wrap(BlockCipher cipher) {
                return CBCBlockCipher.newInstance(cipher);
            }
        },
        CTR {
            @Override BlockCipher wrap(BlockCipher cipher) {
                return SICBlockCipher.newInstance(cipher);
            }
        };

        abstract BlockCipher wrap(BlockCipher cipher);
    }

    // The (cipher, padding) pair is the CIPHER_*/PAD_* identity used by the flexible getInstance and
    // returned by getCipherAlgorithm()/getPaddingAlgorithm(); algByte is the single-byte ALG_* identity.
    // AES counter mode has no flexible mapping in the JC API, so both its cipher and padding are 0 -
    // it is reachable only through the single-byte ALG_*. paddingFactory is null for the unpadded modes.
    private enum CipherAlg {
        DES_CBC_NOPAD(ALG_DES_CBC_NOPAD, CIPHER_DES_CBC, PAD_NOPAD, KeyBuilder.TYPE_DES, Mode.CBC, null),
        DES_CBC_ISO9797_M1(ALG_DES_CBC_ISO9797_M1, CIPHER_DES_CBC, PAD_ISO9797_M1, KeyBuilder.TYPE_DES, Mode.CBC, ZeroBytePadding::new),
        DES_CBC_ISO9797_M2(ALG_DES_CBC_ISO9797_M2, CIPHER_DES_CBC, PAD_ISO9797_M2, KeyBuilder.TYPE_DES, Mode.CBC, ISO7816d4Padding::new),
        DES_CBC_PKCS5(ALG_DES_CBC_PKCS5, CIPHER_DES_CBC, PAD_PKCS5, KeyBuilder.TYPE_DES, Mode.CBC, PKCS7Padding::new),
        DES_ECB_NOPAD(ALG_DES_ECB_NOPAD, CIPHER_DES_ECB, PAD_NOPAD, KeyBuilder.TYPE_DES, Mode.ECB, null),
        DES_ECB_ISO9797_M1(ALG_DES_ECB_ISO9797_M1, CIPHER_DES_ECB, PAD_ISO9797_M1, KeyBuilder.TYPE_DES, Mode.ECB, ZeroBytePadding::new),
        DES_ECB_ISO9797_M2(ALG_DES_ECB_ISO9797_M2, CIPHER_DES_ECB, PAD_ISO9797_M2, KeyBuilder.TYPE_DES, Mode.ECB, ISO7816d4Padding::new),
        DES_ECB_PKCS5(ALG_DES_ECB_PKCS5, CIPHER_DES_ECB, PAD_PKCS5, KeyBuilder.TYPE_DES, Mode.ECB, PKCS7Padding::new),
        AES_CBC_NOPAD(ALG_AES_BLOCK_128_CBC_NOPAD, CIPHER_AES_CBC, PAD_NOPAD, KeyBuilder.TYPE_AES, Mode.CBC, null),
        AES_CBC_ISO9797_M1(ALG_AES_CBC_ISO9797_M1, CIPHER_AES_CBC, PAD_ISO9797_M1, KeyBuilder.TYPE_AES, Mode.CBC, ZeroBytePadding::new),
        AES_CBC_ISO9797_M2(ALG_AES_CBC_ISO9797_M2, CIPHER_AES_CBC, PAD_ISO9797_M2, KeyBuilder.TYPE_AES, Mode.CBC, ISO7816d4Padding::new),
        AES_CBC_PKCS5(ALG_AES_CBC_PKCS5, CIPHER_AES_CBC, PAD_PKCS5, KeyBuilder.TYPE_AES, Mode.CBC, PKCS7Padding::new),
        AES_ECB_NOPAD(ALG_AES_BLOCK_128_ECB_NOPAD, CIPHER_AES_ECB, PAD_NOPAD, KeyBuilder.TYPE_AES, Mode.ECB, null),
        AES_ECB_ISO9797_M1(ALG_AES_ECB_ISO9797_M1, CIPHER_AES_ECB, PAD_ISO9797_M1, KeyBuilder.TYPE_AES, Mode.ECB, ZeroBytePadding::new),
        AES_ECB_ISO9797_M2(ALG_AES_ECB_ISO9797_M2, CIPHER_AES_ECB, PAD_ISO9797_M2, KeyBuilder.TYPE_AES, Mode.ECB, ISO7816d4Padding::new),
        AES_ECB_PKCS5(ALG_AES_ECB_PKCS5, CIPHER_AES_ECB, PAD_PKCS5, KeyBuilder.TYPE_AES, Mode.ECB, PKCS7Padding::new),
        AES_CTR(ALG_AES_CTR, (byte) 0, (byte) 0, KeyBuilder.TYPE_AES, Mode.CTR, null),
        KOREAN_SEED_ECB_NOPAD(ALG_KOREAN_SEED_ECB_NOPAD, CIPHER_KOREAN_SEED_ECB, PAD_NOPAD, KeyBuilder.TYPE_KOREAN_SEED, Mode.ECB, null),
        KOREAN_SEED_CBC_NOPAD(ALG_KOREAN_SEED_CBC_NOPAD, CIPHER_KOREAN_SEED_CBC, PAD_NOPAD, KeyBuilder.TYPE_KOREAN_SEED, Mode.CBC, null);

        final byte algByte;
        final byte cipher;
        final byte padding;
        final byte family;
        final Mode mode;
        final Supplier<BlockCipherPadding> paddingFactory;

        CipherAlg(byte algByte, byte cipher, byte padding, byte family, Mode mode, Supplier<BlockCipherPadding> paddingFactory) {
            this.algByte = algByte;
            this.cipher = cipher;
            this.padding = padding;
            this.family = family;
            this.mode = mode;
            this.paddingFactory = paddingFactory;
        }

        // (cipher, padding) -> entry; null when unrecognised. cipher 0 entries are never matched here.
        static CipherAlg from(byte cipher, byte padding) {
            for (var a : values()) {
                if (a.cipher != 0 && a.cipher == cipher && a.padding == padding) {
                    return a;
                }
            }
            return null;
        }

        // Legacy single-byte ALG_* constant -> entry; null when unrecognised.
        static CipherAlg byByte(byte algorithm) {
            for (var a : values()) {
                if (a.algByte == algorithm) {
                    return a;
                }
            }
            return null;
        }
    }

    private final CipherAlg spec;
    BufferedBlockCipher engine;
    CipherState state = CipherState.UNINITIALIZED;

    // Non-null only for padded encrypt: the engine is unpadded and doFinal() appends this padding
    // manually, matching a card's eager block flush. Null for decrypt and the unpadded modes.
    BlockCipherPadding padding;

    private SymmetricCipherImpl(CipherAlg spec) {
        this.spec = spec;
    }

    // Probed by CipherProxy: an instance for any algorithm this table holds, else null.
    public static Cipher getInstance(byte algorithm) {
        CipherAlg a = CipherAlg.byByte(algorithm);
        return a == null ? null : new SymmetricCipherImpl(a);
    }

    public static Cipher getInstance(byte cipherAlgorithm, byte paddingAlgorithm) {
        CipherAlg a = CipherAlg.from(cipherAlgorithm, paddingAlgorithm);
        return a == null ? null : new SymmetricCipherImpl(a);
    }
    
    @Override
    public void init(Key theKey, byte theMode) throws CryptoException {
        selectCipherEngine(theKey, theMode == MODE_ENCRYPT);
        engine.init(theMode == MODE_ENCRYPT, ((SymmetricKeyImpl) theKey).getParameters());
        state = CipherState.INITIALIZED;
    }

    @Override
    public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen) throws CryptoException {
        if (spec.mode == Mode.ECB) {
            // ECB mode takes no initial vector.
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        selectCipherEngine(theKey, theMode == MODE_ENCRYPT);
        if (bLen != engine.getBlockSize()) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        byte[] iv = JCSystem.makeTransientByteArray(bLen, JCSystem.CLEAR_ON_RESET);
        Util.arrayCopyNonAtomic(bArray, bOff, iv, (short) 0, bLen);
        engine.init(theMode == MODE_ENCRYPT, new ParametersWithIV(((SymmetricKeyImpl) theKey).getParameters(), iv));
        state = CipherState.INITIALIZED;
    }

    @Override
    public byte getAlgorithm() {
        return spec.algByte;
    }

    @Override
    public byte getCipherAlgorithm() {
        return spec.cipher;
    }

    @Override
    public byte getPaddingAlgorithm() {
        return spec.padding;
    }

    @Override
    public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
        if (!state.initialized()) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }

        try {
            short processed = (short) engine.processBytes(inBuff, inOffset, inLength, outBuff, outOffset);
            if (padding != null) {
                // Padded encrypt: every complete block was already flushed by update(), so at most
                // a partial block sits in the engine. Fill a pad block with the remaining bytes
                // plus padding and push it through the engine.
                int blockSize = engine.getBlockSize();
                int buffered = engine.getOutputSize(0);
                byte[] padBlock = new byte[blockSize];
                padding.addPadding(padBlock, buffered);
                processed += (short) engine.processBytes(padBlock, buffered, blockSize - buffered, outBuff, outOffset + processed);
            }
            return (short) (engine.doFinal(outBuff, outOffset + processed) + processed);
        } catch (InvalidCipherTextException | RuntimeException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        return -1;
    }

    @Override
    public short update(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
        if (!state.initialized()) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        return (short) engine.processBytes(inBuff, inOffset, inLength, outBuff, outOffset);
    }

    private void selectCipherEngine(Key theKey, boolean encrypting) {
        if (theKey == null) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (!theKey.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (!(theKey instanceof SymmetricKeyImpl key)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            return;
        }
        if (spec.family != key.type) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }

        BlockCipher modeCipher = spec.mode.wrap(CipherUtils.of(key.type, key.getSize()));
        // A real card's update() flushes every complete block immediately. BouncyCastle's
        // PaddedBufferedBlockCipher withholds the last block on encrypt because it cannot know
        // whether doFinal() still needs to pad it, so padded encrypt runs an unpadded engine and
        // doFinal() appends the padding explicitly. Padded decrypt keeps PaddedBufferedBlockCipher,
        // which holds the final block back so the padding is stripped before anything is written.
        padding = null;
        if (spec.paddingFactory == null) {
            engine = new DefaultBufferedBlockCipher(modeCipher);
        } else if (encrypting) {
            engine = new DefaultBufferedBlockCipher(modeCipher);
            padding = spec.paddingFactory.get();
        } else {
            engine = new PaddedBufferedBlockCipher(modeCipher, spec.paddingFactory.get());
        }
    }
}
