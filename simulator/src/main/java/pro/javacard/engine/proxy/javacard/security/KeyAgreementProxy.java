// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
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

    public static final KeyAgreement getInstance(byte algorithm, boolean externalAccess) throws CryptoException {
        if (externalAccess) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        KeyAgreement instance = KeyAgreementImpl.getInstance(algorithm);
        if (instance == null) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        return instance;
    }
}
