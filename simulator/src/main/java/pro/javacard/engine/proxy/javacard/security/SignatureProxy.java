// SPDX-FileCopyrightText: 2015 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.proxy.javacard.security;

import com.licel.jcardsim.crypto.AsymmetricSignatureImpl;
import com.licel.jcardsim.crypto.SymmetricSignatureImpl;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.Signature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ProxyClass for <code>Signature</code>
 *
 * @see Signature
 */
public class SignatureProxy {

    /**
     * Creates a <code>Signature</code> object instance of the selected algorithm.
     *
     * @param algorithm      the desired Signature algorithm. Valid codes listed in
     *                       ALG_ .. constants above e.g. <A HREF="../../javacard/security/Signature.html#ALG_DES_MAC4_NOPAD"><CODE>ALG_DES_MAC4_NOPAD</CODE></A>
     * @param externalAccess <code>true</code> indicates that the instance will be shared among
     *                       multiple applet instances and that the <code>Signature</code> instance will also be accessed (via a <code>Shareable</code>
     *                       interface) when the owner of the <code>Signature</code> instance is not the currently selected applet.
     *                       If <code>true</code> the implementation must not allocate CLEAR_ON_DESELECT transient space for internal data.
     * @return the <code>Signature</code> object instance of the requested algorithm
     * @throws CryptoException with the following reason codes:<ul>
     *                         <li><code>CryptoException.NO_SUCH_ALGORITHM</code> if the requested algorithm
     *                         or shared access mode is not supported.</ul>
     */
    public static final Signature getInstance(byte algorithm, boolean externalAccess)
            throws CryptoException {
        if (externalAccess) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        Signature instance = SymmetricSignatureImpl.getInstance(algorithm);
        if (instance == null) {
            instance = AsymmetricSignatureImpl.getInstance(algorithm);
        }
        if (instance == null) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        return instance;
    }

    public static final Signature getInstance(byte messageDigestAlgorithm, byte cipherAlgorithm,
                                              byte paddingAlgorithm, boolean externalAccess) throws CryptoException {
        if (externalAccess) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        Signature instance = SymmetricSignatureImpl.getInstance(messageDigestAlgorithm, cipherAlgorithm, paddingAlgorithm);
        if (instance == null) {
            instance = AsymmetricSignatureImpl.getInstance(messageDigestAlgorithm, cipherAlgorithm, paddingAlgorithm);
        }
        if (instance == null) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        return instance;
    }

    public static final class OneShot extends Signature {
        private static final Logger log = LoggerFactory.getLogger(OneShot.class);
        private Signature signature;

        private OneShot() {
            log.debug("Signature.OneShot");
        }

        public static SignatureProxy.OneShot open(byte messageDigestAlgorithm, byte cipherAlgorithm, byte paddingAlgorithm) {
            SignatureProxy.OneShot one = new SignatureProxy.OneShot();
            one.signature = Signature.getInstance(messageDigestAlgorithm, cipherAlgorithm, paddingAlgorithm, false);
            return one;
        }

        // Null after close(); throws ILLEGAL_USE.
        private Signature active() {
            if (signature == null) {
                CryptoException.throwIt(CryptoException.ILLEGAL_USE);
            }
            return signature;
        }

        @Override
        public void init(Key key, byte b) throws CryptoException {
            active().init(key, b);
        }

        @Override
        public void init(Key key, byte b, byte[] bytes, short i, short i1) throws CryptoException {
            active().init(key, b, bytes, i, i1);
        }

        @Override
        public void setInitialDigest(byte[] bytes, short i, short i1, byte[] bytes1, short i2, short i3) throws CryptoException {
            active().setInitialDigest(bytes, i, i1, bytes1, i2, i3);
        }

        @Override
        public byte getAlgorithm() {
            return active().getAlgorithm();
        }

        @Override
        public byte getMessageDigestAlgorithm() {
            return active().getMessageDigestAlgorithm();
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
        public short getLength() throws CryptoException {
            return active().getLength();
        }

        @Override
        public void update(byte[] bytes, short i, short i1) throws CryptoException {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }

        @Override
        public short sign(byte[] bytes, short i, short i1, byte[] bytes1, short i2) throws CryptoException {
            return active().sign(bytes, i, i1, bytes1, i2);
        }

        @Override
        public short signPreComputedHash(byte[] bytes, short i, short i1, byte[] bytes1, short i2) throws CryptoException {
            return active().signPreComputedHash(bytes, i, i1, bytes1, i2);
        }

        @Override
        public boolean verify(byte[] bytes, short i, short i1, byte[] bytes1, short i2, short i3) throws CryptoException {
            return active().verify(bytes, i, i1, bytes1, i2, i3);
        }

        @Override
        public boolean verifyPreComputedHash(byte[] bytes, short i, short i1, byte[] bytes1, short i2, short i3) throws CryptoException {
            return active().verifyPreComputedHash(bytes, i, i1, bytes1, i2, i3);
        }

        public void close() {
            signature = null;
        }
    }
}
