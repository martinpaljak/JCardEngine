// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacardx.crypto.AEADCipher;
import javacardx.crypto.Cipher;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.function.Function;

public final class AuthenticatedSymmetricCipherImpl extends AEADCipher {

    private static final List<Integer> SUPPORTED_TAG_BITS = List.of(128, 120, 112, 104, 96, 64, 32);

    private enum CipherAlg {
        AES_GCM(ALG_AES_GCM, CIPHER_AES_GCM, GCMBlockCipher::newInstance),
        AES_CCM(ALG_AES_CCM, CIPHER_AES_CCM, CCMBlockCipher::newInstance);

        final byte algByte;
        final byte cipher;
        final Function<BlockCipher, AEADBlockCipher> engineFactory;

        CipherAlg(byte algByte, byte cipher, Function<BlockCipher, AEADBlockCipher> engineFactory) {
            this.algByte = algByte;
            this.cipher = cipher;
            this.engineFactory = engineFactory;
        }

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

    AEADBlockCipher engine;
    AEADParameters parameters;

    CipherState state;

    byte initMode;
    short initMsgLen;
    short totalMsgLen;
    short initAADLen;
    short tagBytes;

    // Key and nonce retained from init so the tag can be recomputed from the recovered plaintext on DECRYPT.
    private byte[] keyBytes;
    private byte[] ivBytes;
    // AAD bytes seen during the current operation, the tag produced by an ENCRYPT doFinal, and the
    // plaintext recovered by a DECRYPT doFinal.
    private final ByteArrayOutputStream aadSeen = new ByteArrayOutputStream();
    private byte[] computedTag;
    private byte[] recoveredPlaintext;

    private AuthenticatedSymmetricCipherImpl(CipherAlg spec) {
        this.spec = spec;
        this.state = CipherState.UNINITIALIZED;
    }

    public static Cipher getInstance(byte algorithm) {
        CipherAlg a = CipherAlg.byByte(algorithm);
        return a == null ? null : new AuthenticatedSymmetricCipherImpl(a);
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
        return 0;
    }

    @Override
    public void init(Key theKey, byte theMode) throws CryptoException {
        // Only GCM operates in online mode (unknown message length up front).
        if (spec.algByte != ALG_AES_GCM) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }

        if ((theMode != MODE_DECRYPT) && (theMode != MODE_ENCRYPT)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }

        byte[] iv = new byte[12];

        selectCipherEngine(theKey);

        ParametersWithIV parametersWithIV = new ParametersWithIV(((SymmetricKeyImpl) theKey).getParameters(), iv);
        try {
            engine.init(theMode == MODE_ENCRYPT, parametersWithIV);
        } catch (RuntimeException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }

        rememberKeyAndIV(theKey, iv);
        initMode = theMode;
        tagBytes = 16;
        state = CipherState.INITIALIZED;
    }

    @Override
    public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen) throws CryptoException {
        // Only GCM operates in online mode (unknown message length up front).
        if (spec.algByte != ALG_AES_GCM) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }

        if ((theMode != MODE_DECRYPT) && (theMode != MODE_ENCRYPT)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }

        // Only the 12-byte IV recommended by NIST SP 800-38D 5.2.1.1.
        if (bLen != 12) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }

        selectCipherEngine(theKey);
        byte[] iv = JCSystem.makeTransientByteArray(bLen, JCSystem.CLEAR_ON_RESET);
        Util.arrayCopyNonAtomic(bArray, bOff, iv, (short) 0, bLen);
        ParametersWithIV parametersWithIV = new ParametersWithIV(((SymmetricKeyImpl) theKey).getParameters(), iv);
        try {
            engine.init(theMode == MODE_ENCRYPT, parametersWithIV);
        } catch (RuntimeException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }

        rememberKeyAndIV(theKey, iv);
        initMode = theMode;
        tagBytes = 16;
        state = CipherState.INITIALIZED;
    }

    @Override
    public void init(Key theKey, byte theMode, byte[] nonceBuf, short nonceOff, short nonceLen, short adataLen, short messageLen, short tagSize) throws CryptoException {
        if ((theMode != MODE_DECRYPT) && (theMode != MODE_ENCRYPT)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }

        // Zero message length or tag size signals an online-mode call, which this offline init does not serve.
        if ((messageLen == 0) || (tagSize == 0)) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }

        // Only the 12-byte nonce recommended by NIST SP 800-38D 5.2.1.1.
        if (nonceLen != 12) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }

        selectCipherEngine(theKey);

        byte[] iv_nonce = JCSystem.makeTransientByteArray(nonceLen, JCSystem.CLEAR_ON_RESET);
        Util.arrayCopyNonAtomic(nonceBuf, nonceOff, iv_nonce, (short) 0, nonceLen);

        rememberKeyAndIV(theKey, iv_nonce);
        parameters = new AEADParameters(new KeyParameter(keyBytes), tagSize * Byte.SIZE, iv_nonce);

        try {
            engine.init(theMode == MODE_ENCRYPT, parameters);
        } catch (RuntimeException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }

        initMode = theMode;
        initMsgLen = messageLen;
        initAADLen = adataLen;
        tagBytes = tagSize;
        totalMsgLen = 0;
        state = CipherState.INITIALIZED;
    }

    @Override
    public void updateAAD(byte[] aadBuf, short aadOff, short aadLen) throws CryptoException {
        if (!state.initialized()) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }

        if (spec.algByte == ALG_AES_CCM) {
            if (aadLen != initAADLen) {
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            }
        }

        engine.processAADBytes(aadBuf, aadOff, aadLen);
        aadSeen.write(aadBuf, aadOff, aadLen);
    }

    @Override
    public short update(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
        if (!state.initialized()) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }

        short processedBytes = (short) engine.processBytes(inBuff, inOffset, inLength, outBuff, outOffset);
        totalMsgLen += inLength;
        return processedBytes;
    }

    @Override
    public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
        if (!state.initialized()) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }

        if (spec.algByte == ALG_AES_CCM) {
            if (engine.getMac().length == 0) {
                CryptoException.throwIt(CryptoException.ILLEGAL_USE);
            }

            totalMsgLen += inLength;
            if (totalMsgLen != initMsgLen) {
                CryptoException.throwIt(CryptoException.ILLEGAL_USE);
            }
        }

        if (initMode == MODE_DECRYPT) {
            return decryptFinal(inBuff, inOffset, inLength, outBuff, outOffset);
        }

        return encryptFinal(inBuff, inOffset, inLength, outBuff, outOffset);
    }

    // ENCRYPT: emit only the ciphertext; keep the tag for a later retrieveTag().
    private short encryptFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
        byte[] scratch = new byte[engine.getOutputSize(inLength)];
        try {
            int produced = engine.processBytes(inBuff, inOffset, inLength, scratch, 0);
            produced += engine.doFinal(scratch, produced);
            short ciphertextLen = (short) (produced - tagBytes);
            Util.arrayCopyNonAtomic(scratch, (short) 0, outBuff, outOffset, ciphertextLen);
            computedTag = Arrays.copyOfRange(scratch, ciphertextLen, produced);
            state = CipherState.FINALIZED;
            return ciphertextLen;
        } catch (InvalidCipherTextException | RuntimeException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        return -1;
    }

    // DECRYPT: emit only the plaintext, with no tag verification. verifyTag() is the sole verifier.
    // The data transform is symmetric (the CTR keystream depends only on key and nonce, not on the AAD),
    // so a fresh ENCRYPT-mode engine over the ciphertext yields the plaintext as its leading output bytes.
    private short decryptFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
        try {
            byte[] ciphertext = new byte[inLength];
            Util.arrayCopyNonAtomic(inBuff, inOffset, ciphertext, (short) 0, inLength);
            byte[] out = aeadEncrypt(ciphertext, new byte[0], 128);
            byte[] plaintext = Arrays.copyOfRange(out, 0, ciphertext.length);
            Util.arrayCopyNonAtomic(plaintext, (short) 0, outBuff, outOffset, (short) plaintext.length);
            recoveredPlaintext = plaintext;
            state = CipherState.FINALIZED;
            return (short) plaintext.length;
        } catch (RuntimeException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        return -1;
    }

    // Run a fresh ENCRYPT engine over the data with the retained key+nonce and given AAD and tag length,
    // returning ciphertext followed by the authentication tag. BouncyCastle CCM getMac() is unreliable, so
    // the tag is always taken from the trailing bytes of this output.
    private byte[] aeadEncrypt(byte[] data, byte[] aad, int macBits) {
        AEADBlockCipher fresh = spec.engineFactory.apply(SymmetricEngines.of(KeyBuilder.TYPE_AES, (short) (keyBytes.length * Byte.SIZE)));
        fresh.init(true, new AEADParameters(new KeyParameter(keyBytes), macBits, ivBytes, aad));
        byte[] scratch = new byte[fresh.getOutputSize(data.length)];
        try {
            int produced = fresh.processBytes(data, 0, data.length, scratch, 0);
            produced += fresh.doFinal(scratch, produced);
            return Arrays.copyOfRange(scratch, 0, produced);
        } catch (InvalidCipherTextException ex) {
            throw new IllegalStateException(ex);
        }
    }

    @Override
    public short retrieveTag(byte[] tagBuf, short tagOff, short tagLen) throws CryptoException {
        if (state != CipherState.FINALIZED) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }

        if (initMode != MODE_ENCRYPT) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }

        if (!SUPPORTED_TAG_BITS.contains(tagLen * Byte.SIZE)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }

        Util.arrayCopyNonAtomic(computedTag, (short) 0, tagBuf, tagOff, tagLen);
        return tagLen;
    }

    @Override
    public boolean verifyTag(byte[] receivedTagBuf, short receivedTagOff, short receivedTagLen, short requiredTagLen) throws CryptoException {
        if (state != CipherState.FINALIZED) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }

        if (initMode != MODE_DECRYPT) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }

        if (!SUPPORTED_TAG_BITS.contains(requiredTagLen * Byte.SIZE)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }

        byte[] out = aeadEncrypt(recoveredPlaintext, aadSeen.toByteArray(), requiredTagLen * Byte.SIZE);
        return Arrays.areEqual(out, recoveredPlaintext.length, recoveredPlaintext.length + requiredTagLen,
                receivedTagBuf, receivedTagOff, receivedTagOff + requiredTagLen);
    }

    private void selectCipherEngine(Key theKey) {
        if (theKey == null) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (!theKey.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (!(theKey instanceof SymmetricKeyImpl)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }

        SymmetricKeyImpl key = (SymmetricKeyImpl) theKey;
        if (!SymmetricKeyImpl.KF_AES.contains(key.getType())) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        try {
            engine = spec.engineFactory.apply(SymmetricEngines.of(key.getType(), key.getSize()));
        } catch (RuntimeException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
    }

    private void rememberKeyAndIV(Key theKey, byte[] iv) {
        SymmetricKeyImpl key = (SymmetricKeyImpl) theKey;
        keyBytes = new byte[key.getSize() / 8];
        key.getKey(keyBytes, (short) 0);
        ivBytes = iv.clone();
        aadSeen.reset();
        computedTag = null;
        recoveredPlaintext = null;
    }
}
