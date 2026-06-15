// SPDX-FileCopyrightText: 2015 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.proxy.javacardx.crypto;

import com.licel.jcardsim.crypto.AsymmetricCipherImpl;
import com.licel.jcardsim.crypto.AuthenticatedSymmetricCipherImpl;
import com.licel.jcardsim.crypto.SymmetricCipherImpl;
import javacard.security.CryptoException;
import javacard.security.Key;
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
    public static final Cipher getInstance(byte algorithm, boolean externalAccess) throws CryptoException {
        if (externalAccess) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        Cipher instance = SymmetricCipherImpl.getInstance(algorithm);
        if (instance == null) {
            instance = AsymmetricCipherImpl.getInstance(algorithm);
        }
        if (instance == null) {
            instance = AuthenticatedSymmetricCipherImpl.getInstance(algorithm);
        }
        if (instance == null) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        return instance;
    }

    public static final Cipher getInstance(byte cipherAlgorithm, byte paddingAlgorithm, boolean externalAccess) throws CryptoException {
        if (externalAccess) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        Cipher instance = SymmetricCipherImpl.getInstance(cipherAlgorithm, paddingAlgorithm);
        if (instance == null) {
            instance = AsymmetricCipherImpl.getInstance(cipherAlgorithm, paddingAlgorithm);
        }
        if (instance == null) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        return instance;
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

        // Null after close(); throws ILLEGAL_USE.
        private Cipher active() {
            if (cipher == null) {
                CryptoException.throwIt(CryptoException.ILLEGAL_USE);
            }
            return cipher;
        }

        @Override
        public void init(Key key, byte mode) throws CryptoException {
            active().init(key, mode);
        }

        @Override
        public void init(Key key, byte mode, byte[] bArray, short bOff, short bLen) throws CryptoException {
            active().init(key, mode, bArray, bOff, bLen);
        }

        @Override
        public byte getAlgorithm() {
            return active().getAlgorithm();
        }

        @Override
        public byte getCipherAlgorithm() {
            return active().getCipherAlgorithm();
        }

        @Override
        public byte getPaddingAlgorithm() {
            return active().getPaddingAlgorithm();
        }

        @Override
        public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
            return active().doFinal(inBuff, inOffset, inLength, outBuff, outOffset);
        }

        @Override
        public short update(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
            // Multi-part update is not allowed on OneShot (JC 3.2 Cipher.OneShot.update)
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
            return 0;
        }
    }
}
