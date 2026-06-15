// SPDX-FileCopyrightText: 2015 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.proxy.javacard.security;

import com.licel.jcardsim.crypto.KeyAgreementImpl;
import javacard.security.CryptoException;
import javacard.security.KeyAgreement;

/**
 * ProxyClass for <code>KeyAgreement</code>
 *
 * @see KeyAgreement
 */
public class KeyAgreementProxy {
    /**
     * Creates a <CODE>KeyAgreement</CODE> object instance of the selected algorithm.
     *
     * @param algorithm      the desired key agreement algorithm
     *                       Valid codes listed in ALG_ .. constants above, for example, <CODE>ALG_EC_SVDP_DH</CODE>
     * @param externalAccess if <code>true</code> indicates that the instance will be shared among
     *                       multiple applet instances and that the <code>KeyAgreement</code> instance will also be accessed (via a <code>Shareable</code>
     *                       interface) when the owner of the <code>KeyAgreement</code> instance is not the currently selected applet.
     *                       If <code>true</code> the implementation must not
     *                       allocate <code>CLEAR_ON_DESELECT</code> transient space for internal data.
     * @return the KeyAgreement object instance of the requested algorithm
     * @throws CryptoException with the following reason codes:
     *                         <ul>
     *                         <li><code>CryptoException.NO_SUCH_ALGORITHM</code> if the requested
     *                         algorithm or shared access mode is not supported.
     *                         </ul>
     */
    public static final KeyAgreement getInstance(byte algorithm, boolean externalAccess)
            throws CryptoException {
        if (externalAccess) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        return new KeyAgreementImpl(algorithm);
    }
}
