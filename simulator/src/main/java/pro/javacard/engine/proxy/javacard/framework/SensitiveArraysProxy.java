// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.proxy.javacard.framework;

import com.licel.jcardsim.base.Simulator;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;

import java.util.Arrays;
import java.util.Objects;

/**
 * ProxyClass for <code>SensitiveArrays</code>
 */
@SuppressWarnings("unused")
public final class SensitiveArraysProxy {

    public static void assertIntegrity(Object obj) {
        Objects.requireNonNull(obj);
        if (!isIntegritySensitive(obj)) {
            SystemException.throwIt(SystemException.ILLEGAL_VALUE);
        }
        // TODO: check for integrity.
    }

    public static boolean isIntegritySensitive(Object obj) {
        return Simulator.current().getTransientMemory().isSensitive(obj);
    }

    public static boolean isIntegritySensitiveArraysSupported() {
        return true;
    }

    public static short clearArray(Object obj) {
        Objects.requireNonNull(obj);
        short dim = 0;
        if (obj instanceof byte[] arr) {
            dim = (short) arr.length;
            Arrays.fill(arr, (byte) 0);
        } else if (obj instanceof short[] arr) {
            dim = (short) arr.length;
            Arrays.fill(arr, (short) 0);
        } else if (obj instanceof boolean[] arr) {
            dim = (short) arr.length;
            Arrays.fill(arr, false);
        } else if (obj instanceof Object[] arr) {
            dim = (short) arr.length;
            Arrays.fill(arr, null);
        } else {
            SystemException.throwIt(SystemException.ILLEGAL_VALUE);
        }
        return dim;
    }

    public static Object makeIntegritySensitiveArray(byte type, byte memory, short length) {
        if (length < 0) {
            throw new NegativeArraySizeException();
        }
        if (memory == JCSystem.MEMORY_TYPE_PERSISTENT) {
            switch (type) {
                case JCSystem.ARRAY_TYPE_BOOLEAN:
                    return new boolean[length];
                case JCSystem.ARRAY_TYPE_BYTE:
                    return new byte[length];
                case JCSystem.ARRAY_TYPE_SHORT:
                    return new short[length];
                case JCSystem.ARRAY_TYPE_OBJECT:
                    return new Object[length];
                case JCSystem.ARRAY_TYPE_INT:
                    return new int[length];
                default:
                    SystemException.throwIt(SystemException.ILLEGAL_VALUE);
            }
        } else if (memory == JCSystem.MEMORY_TYPE_TRANSIENT_RESET || memory == JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT) {
            byte event = memory == JCSystem.MEMORY_TYPE_TRANSIENT_RESET ?
                    JCSystem.CLEAR_ON_RESET : JCSystem.CLEAR_ON_DESELECT;
            switch (type) {
                case JCSystem.ARRAY_TYPE_BOOLEAN:
                    return JCSystem.makeTransientBooleanArray(length, event);
                case JCSystem.ARRAY_TYPE_BYTE:
                    return JCSystem.makeTransientByteArray(length, event);
                case JCSystem.ARRAY_TYPE_SHORT:
                    return JCSystem.makeTransientShortArray(length, event);
                case JCSystem.ARRAY_TYPE_OBJECT:
                    return JCSystem.makeTransientObjectArray(length, event);
                case JCSystem.ARRAY_TYPE_INT:
                    SystemException.throwIt(SystemException.ILLEGAL_VALUE);
                    break;
                default:
                    SystemException.throwIt(SystemException.ILLEGAL_VALUE);
            }
        } else {
            SystemException.throwIt(SystemException.ILLEGAL_VALUE);
        }
        return null;
    }
}
