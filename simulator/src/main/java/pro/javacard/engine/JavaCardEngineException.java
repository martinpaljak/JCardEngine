// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine;

/** thrown when JCRE is supposed to "eat" the exception */
public class JavaCardEngineException extends RuntimeException {
    public JavaCardEngineException(String message) {
        super(message);
    }

    public JavaCardEngineException(String message, Exception cause) {
        super(message, cause);
    }
}
