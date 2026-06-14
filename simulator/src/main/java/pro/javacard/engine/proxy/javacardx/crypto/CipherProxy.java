// SPDX-FileCopyrightText: 2015 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.proxy.javacardx.crypto;

import com.licel.jcardsim.crypto.AsymmetricCipherImpl;
import com.licel.jcardsim.crypto.AuthenticatedSymmetricCipherImpl;
import com.licel.jcardsim.crypto.SymmetricCipherImpl;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacardx.crypto.AEADCipher;
import javacardx.crypto.Cipher;

/**
 * ProxyClass for <code>Cipher</code>
 *
 * @see Cipher
 */
@SuppressWarnings("deprecation")
public class CipherProxy {
    /**
     * Creates a <code>Cipher</code> object instance of the selected algorithm.
     *
     * @param algorithm      the desired Cipher algorithm. Valid codes listed in
     *                       ALG_ .. constants above, for example, {@link Cipher#ALG_DES_CBC_NOPAD}
     * @param externalAccess indicates that the instance will be shared among
     *                       multiple applet instances and that the <code>Cipher</code> instance will also be accessed (via a <code>Shareable</code>
     *                       interface) when the owner of the <code>Cipher</code> instance is not the currently selected applet.
     *                       If <code>true</code> the implementation must not allocate CLEAR_ON_DESELECT transient space for internal data.
     * @return the <code>Cipher</code> object instance of the requested algorithm
     * @throws CryptoException with the following reason codes:
     *                         <ul>
     *                          <li><code>CryptoException.NO_SUCH_ALGORITHM</code> if the requested algorithm is not supported
     *                          or shared access mode is not supported.
     *                         </ul>
     */
    public static final Cipher getInstance(byte algorithm, boolean externalAccess)
            throws CryptoException {
        Cipher instance = null;
        if (externalAccess) {
            CryptoException.throwIt((short) 3);
        }

        switch (algorithm) {
            case Cipher.ALG_DES_CBC_NOPAD:
            case Cipher.ALG_DES_CBC_ISO9797_M1:
            case Cipher.ALG_DES_CBC_ISO9797_M2:
            case Cipher.ALG_DES_CBC_PKCS5:
            case Cipher.ALG_DES_ECB_NOPAD:
            case Cipher.ALG_DES_ECB_ISO9797_M1:
            case Cipher.ALG_DES_ECB_ISO9797_M2:
            case Cipher.ALG_DES_ECB_PKCS5:
            case Cipher.ALG_AES_BLOCK_128_CBC_NOPAD:
            case Cipher.ALG_AES_BLOCK_128_ECB_NOPAD:
            case Cipher.ALG_AES_CBC_ISO9797_M2:
            case Cipher.ALG_AES_CTR:
            case Cipher.ALG_KOREAN_SEED_ECB_NOPAD:
            case Cipher.ALG_KOREAN_SEED_CBC_NOPAD:
                instance = new SymmetricCipherImpl(algorithm);
                break;
            case Cipher.ALG_RSA_PKCS1:
            case Cipher.ALG_RSA_NOPAD:
            case Cipher.ALG_RSA_ISO14888:
            case Cipher.ALG_RSA_ISO9796:
            case Cipher.ALG_RSA_PKCS1_OAEP:
                instance = new AsymmetricCipherImpl(algorithm);
                break;
            case AEADCipher.ALG_AES_GCM:
            case AEADCipher.ALG_AES_CCM:
                instance = new AuthenticatedSymmetricCipherImpl(algorithm);
                break;

            default:
                CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
                break;
        }
        return instance;
    }

    public static final Cipher getInstance(byte cipherAlgorithm, byte paddingAlgorithm, boolean externalAccess)
            throws CryptoException {
        return getInstance(resolveAlgorithm(cipherAlgorithm, paddingAlgorithm), externalAccess);
    }

    // Maps a (cipher, padding) pair to the single-argument ALG_* code expected by getInstance(byte, boolean),
    // or throws NO_SUCH_ALGORITHM for unrecognised combinations.
    private static byte resolveAlgorithm(byte cipherAlgorithm, byte paddingAlgorithm) {
        switch (cipherAlgorithm) {
            case Cipher.CIPHER_DES_CBC:
                switch (paddingAlgorithm) {
                    case Cipher.PAD_NOPAD:
                        return Cipher.ALG_DES_CBC_NOPAD;
                    case Cipher.PAD_ISO9797_M1:
                        return Cipher.ALG_DES_CBC_ISO9797_M1;
                    case Cipher.PAD_ISO9797_M2:
                        return Cipher.ALG_DES_CBC_ISO9797_M2;
                    case Cipher.PAD_PKCS5:
                        return Cipher.ALG_DES_CBC_PKCS5;
                }
                break;
            case Cipher.CIPHER_DES_ECB:
                switch (paddingAlgorithm) {
                    case Cipher.PAD_NOPAD:
                        return Cipher.ALG_DES_ECB_NOPAD;
                    case Cipher.PAD_ISO9797_M1:
                        return Cipher.ALG_DES_ECB_ISO9797_M1;
                    case Cipher.PAD_ISO9797_M2:
                        return Cipher.ALG_DES_ECB_ISO9797_M2;
                    case Cipher.PAD_PKCS5:
                        return Cipher.ALG_DES_ECB_PKCS5;
                }
                break;
            case Cipher.CIPHER_AES_CBC:
                switch (paddingAlgorithm) {
                    case Cipher.PAD_NOPAD:
                        return Cipher.ALG_AES_BLOCK_128_CBC_NOPAD;
                    case Cipher.PAD_ISO9797_M2:
                        return Cipher.ALG_AES_CBC_ISO9797_M2;
                }
                break;
            case Cipher.CIPHER_AES_ECB:
                switch (paddingAlgorithm) {
                    case Cipher.PAD_NOPAD:
                        return Cipher.ALG_AES_BLOCK_128_ECB_NOPAD;
                }
                break;
            case Cipher.CIPHER_RSA:
                switch (paddingAlgorithm) {
                    case Cipher.PAD_NOPAD:
                        return Cipher.ALG_RSA_NOPAD;
                    case Cipher.PAD_PKCS1:
                        return Cipher.ALG_RSA_PKCS1;
                    case Cipher.PAD_PKCS1_OAEP:
                        return Cipher.ALG_RSA_PKCS1_OAEP;
                }
                break;
        }
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        return 0; // not reached
    }

    public static final class OneShot extends Cipher {
        private Cipher cipher;

        private OneShot() {
        }

        public static CipherProxy.OneShot open(byte cipherAlgorithm, byte paddingAlgorithm) throws CryptoException {
            CipherProxy.OneShot one = new CipherProxy.OneShot();
            one.cipher = Cipher.getInstance(cipherAlgorithm, paddingAlgorithm, false);
            return one;
        }

        public void close() {
            cipher = null;
        }

        @Override
        public void init(Key key, byte mode) throws CryptoException {
            cipher.init(key, mode);
        }

        @Override
        public void init(Key key, byte mode, byte[] bArray, short bOff, short bLen) throws CryptoException {
            cipher.init(key, mode, bArray, bOff, bLen);
        }

        @Override
        public byte getAlgorithm() {
            return cipher.getAlgorithm();
        }

        @Override
        public byte getCipherAlgorithm() {
            return cipher.getCipherAlgorithm();
        }

        @Override
        public byte getPaddingAlgorithm() {
            return cipher.getPaddingAlgorithm();
        }

        @Override
        public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
            return cipher.doFinal(inBuff, inOffset, inLength, outBuff, outOffset);
        }

        @Override
        public short update(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
            // Multi-part update is not allowed on OneShot (JC 3.2 Cipher.OneShot.update)
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
            return 0;
        }
    }
}
