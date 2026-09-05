// SPDX-FileCopyrightText: 2015 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.proxy.javacard.framework;

/**
 * ProxyClass for <code>CardRuntimeException</code>
 *
 * @see javacard.framework.CardRuntimeException
 */
public class CardRuntimeExceptionProxy extends RuntimeException {
    private static final long serialVersionUID = -1010907071061020447L;

    private short reason;

    /**
     * Constructs a CardRuntimeException instance with the specified reason.
     * To conserve on resources, use the <code>throwIt()</code> method
     * to employ the Java Card runtime environment-owned instance of this class.
     *
     * @param reason the reason for the exception
     */
    public CardRuntimeExceptionProxy(short reason) {
        this.reason = reason;
    }

    /**
     * Get reason code
     *
     * @return the reason for the exception
     */
    public short getReason() {
        return reason;
    }

    /**
     * Set reason code
     *
     * @param reason the reason for the exception
     */
    public void setReason(short reason) {
        this.reason = reason;
    }

    /**
     * Throws the Java Card runtime environment-owned instance of the <code>CardRuntimeException</code> class with the
     * specified reason.
     * <p>Java Card runtime environment-owned instances of exception classes are temporary Java Card runtime environment Entry Point Objects
     * and can be accessed from any applet context. References to these temporary objects
     * cannot be stored in class variables or instance variables or array components.
     * See <em>Runtime Environment Specification for the Java Card Platform</em>, section 6.2.1 for details.
     *
     * @param reason the reason for the exception
     * @throws CardRuntimeExceptionProxy always
     */
    public static void throwIt(short reason) throws CardRuntimeExceptionProxy {
        throw new CardRuntimeExceptionProxy(reason);
    }
}
