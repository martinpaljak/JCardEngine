// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation <code>Cipher</code> with symmetric keys based
 * on BouncyCastle CryptoAPI.
 *
 * @see Cipher
 */
@SuppressWarnings("deprecation") // bc ..
public class SymmetricCipherImpl extends Cipher {

    private static final Logger log = LoggerFactory.getLogger(SymmetricCipherImpl.class);
    byte algorithm;
    BufferedBlockCipher engine;
    boolean isInitialized;

    // Non-null only for padded encrypt: the engine is an unpadded BufferedBlockCipher and
    // doFinal() appends this padding manually. Null for decrypt (PaddedBufferedBlockCipher
    // strips padding itself), and for nopad and CTR algorithms.
    BlockCipherPadding padding;

    public SymmetricCipherImpl(byte algorithm) {
        this.algorithm = algorithm;
    }

    public void init(Key theKey, byte theMode) throws CryptoException {
        selectCipherEngine(theKey, theMode == MODE_ENCRYPT);
        engine.init(theMode == MODE_ENCRYPT, ((SymmetricKeyImpl) theKey).getParameters());
        isInitialized = true;
    }

    public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen) throws CryptoException {
        switch (algorithm) {
            case ALG_DES_ECB_NOPAD:
            case ALG_DES_ECB_ISO9797_M1:
            case ALG_DES_ECB_ISO9797_M2:
            case ALG_DES_ECB_PKCS5:
            case ALG_KOREAN_SEED_ECB_NOPAD:
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
                break;
            case ALG_DES_CBC_NOPAD:
            case ALG_DES_CBC_ISO9797_M1:
            case ALG_DES_CBC_ISO9797_M2:
            case ALG_DES_CBC_PKCS5:
                if (bLen != (short) 8) {
                    CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
                }
                break;
            case ALG_AES_BLOCK_128_CBC_NOPAD:
            case ALG_AES_CBC_ISO9797_M2:
                if (bLen != (short) 16) {
                    CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
                }
                break;
            default:
                log.trace("No init for cipher algo: " + algorithm);
        }
        selectCipherEngine(theKey, theMode == MODE_ENCRYPT);
        byte[] iv = JCSystem.makeTransientByteArray(bLen, JCSystem.CLEAR_ON_RESET);
        Util.arrayCopyNonAtomic(bArray, bOff, iv, (short) 0, bLen);
        engine.init(theMode == MODE_ENCRYPT, new ParametersWithIV(((SymmetricKeyImpl) theKey).getParameters(), iv));
        isInitialized = true;
    }

    public byte getAlgorithm() {
        return algorithm;
    }

    public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
        if (!isInitialized) {
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

    public short update(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
        if (!isInitialized) {
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
        if (!(theKey instanceof SymmetricKeyImpl)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        if (!checkKeyCompatibility(theKey)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }

        SymmetricKeyImpl key = (SymmetricKeyImpl) theKey;
        padding = null;
        BlockCipher modeCipher = null;
        switch (algorithm) {
            case ALG_DES_CBC_NOPAD:
            case ALG_AES_BLOCK_128_CBC_NOPAD:
            case ALG_KOREAN_SEED_CBC_NOPAD:
                engine = new BufferedBlockCipher(CBCBlockCipher.newInstance(key.getCipher()));
                break;
            case ALG_DES_CBC_ISO9797_M1:
                modeCipher = CBCBlockCipher.newInstance(key.getCipher());
                padding = new ZeroBytePadding();
                break;
            case ALG_DES_CBC_ISO9797_M2:
                modeCipher = CBCBlockCipher.newInstance(key.getCipher());
                padding = new ISO7816d4Padding();
                break;
            case ALG_DES_CBC_PKCS5:
                modeCipher = CBCBlockCipher.newInstance(key.getCipher());
                padding = new PKCS7Padding();
                break;
            case ALG_DES_ECB_NOPAD:
            case ALG_AES_BLOCK_128_ECB_NOPAD:
            case ALG_KOREAN_SEED_ECB_NOPAD:
                engine = new BufferedBlockCipher(key.getCipher());
                break;
            case ALG_DES_ECB_ISO9797_M1:
                modeCipher = key.getCipher();
                padding = new ZeroBytePadding();
                break;
            case ALG_DES_ECB_ISO9797_M2:
                modeCipher = key.getCipher();
                padding = new ISO7816d4Padding();
                break;
            case ALG_DES_ECB_PKCS5:
                modeCipher = key.getCipher();
                padding = new PKCS7Padding();
                break;
            case ALG_AES_CBC_ISO9797_M2:
                modeCipher = CBCBlockCipher.newInstance(key.getCipher());
                padding = new ISO7816d4Padding();
                break;
            case ALG_AES_CTR:
                engine = new BufferedBlockCipher(new SICBlockCipher(key.getCipher()));
                break;
            default:
                CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
                break;
        }

        // A real card's update() flushes every complete block immediately (two blocks in -> 32
        // bytes out). BouncyCastle's PaddedBufferedBlockCipher withholds the last block on
        // encrypt because it cannot know whether doFinal() still needs to append padding to it.
        // To match card behaviour, padded encrypt uses an unpadded BufferedBlockCipher (flushes
        // complete blocks immediately) and doFinal() appends the padding explicitly. Padded
        // decrypt keeps PaddedBufferedBlockCipher, which holds the final block back so the
        // padding bytes are stripped before anything is written to outBuff, as update() requires.
        if (padding != null) {
            if (encrypting) {
                engine = new BufferedBlockCipher(modeCipher);
            } else {
                engine = new PaddedBufferedBlockCipher(modeCipher, padding);
                padding = null;
            }
        }
    }

    private boolean checkKeyCompatibility(Key theKey) {
        switch (theKey.getType()) {
            case KeyBuilder.TYPE_DES:
            case KeyBuilder.TYPE_DES_TRANSIENT_RESET:
            case KeyBuilder.TYPE_DES_TRANSIENT_DESELECT:
                if ((algorithm == Cipher.ALG_DES_CBC_NOPAD) ||
                    (algorithm == Cipher.ALG_DES_CBC_ISO9797_M1) ||
                    (algorithm == Cipher.ALG_DES_CBC_ISO9797_M2) ||
                    (algorithm == Cipher.ALG_DES_CBC_PKCS5) ||
                    (algorithm == Cipher.ALG_DES_ECB_NOPAD) ||
                    (algorithm == Cipher.ALG_DES_ECB_ISO9797_M1) ||
                    (algorithm == Cipher.ALG_DES_ECB_ISO9797_M2) ||
                    (algorithm == Cipher.ALG_DES_ECB_PKCS5)) {
                    return true;
                }
                break;

            case KeyBuilder.TYPE_AES:
            case KeyBuilder.TYPE_AES_TRANSIENT_RESET:
            case KeyBuilder.TYPE_AES_TRANSIENT_DESELECT:
                if ((algorithm == Cipher.ALG_AES_CTR) ||
                    (algorithm == Cipher.ALG_AES_BLOCK_128_CBC_NOPAD) ||
                    (algorithm == Cipher.ALG_AES_BLOCK_128_ECB_NOPAD) ||
                    (algorithm == Cipher.ALG_AES_CBC_ISO9797_M1) ||
                    (algorithm == Cipher.ALG_AES_CBC_ISO9797_M2) ||
                    (algorithm == Cipher.ALG_AES_CBC_PKCS5) ||
                    (algorithm == Cipher.ALG_AES_ECB_ISO9797_M1) ||
                    (algorithm == Cipher.ALG_AES_ECB_ISO9797_M2) ||
                    (algorithm == Cipher.ALG_AES_ECB_PKCS5)) {
                    return true;
                }
                break;


            case KeyBuilder.TYPE_KOREAN_SEED:
            case KeyBuilder.TYPE_KOREAN_SEED_TRANSIENT_RESET:
            case KeyBuilder.TYPE_KOREAN_SEED_TRANSIENT_DESELECT:
                if ((algorithm == Cipher.ALG_KOREAN_SEED_CBC_NOPAD) ||
                    (algorithm == Cipher.ALG_KOREAN_SEED_ECB_NOPAD)) {
                    return true;
                }
                break;
        }

        return false;

    }

    public byte getPaddingAlgorithm() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public byte getCipherAlgorithm() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
