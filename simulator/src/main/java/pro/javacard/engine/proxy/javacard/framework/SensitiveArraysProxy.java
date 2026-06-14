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
        Object array = null;
        if (memory == JCSystem.MEMORY_TYPE_PERSISTENT) {
            switch (type) {
                case JCSystem.ARRAY_TYPE_BOOLEAN:
                    array = new boolean[length];
                    break;
                case JCSystem.ARRAY_TYPE_BYTE:
                    array = new byte[length];
                    break;
                case JCSystem.ARRAY_TYPE_SHORT:
                    array = new short[length];
                    break;
                case JCSystem.ARRAY_TYPE_OBJECT:
                    array = new Object[length];
                    break;
                case JCSystem.ARRAY_TYPE_INT:
                    array = new int[length];
                    break;
                default:
                    SystemException.throwIt(SystemException.ILLEGAL_VALUE);
            }
        } else if (memory == JCSystem.MEMORY_TYPE_TRANSIENT_RESET || memory == JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT) {
            byte event = memory == JCSystem.MEMORY_TYPE_TRANSIENT_RESET ?
                    JCSystem.CLEAR_ON_RESET : JCSystem.CLEAR_ON_DESELECT;
            switch (type) {
                case JCSystem.ARRAY_TYPE_BOOLEAN:
                    array = JCSystem.makeTransientBooleanArray(length, event);
                    break;
                case JCSystem.ARRAY_TYPE_BYTE:
                    array = JCSystem.makeTransientByteArray(length, event);
                    break;
                case JCSystem.ARRAY_TYPE_SHORT:
                    array = JCSystem.makeTransientShortArray(length, event);
                    break;
                case JCSystem.ARRAY_TYPE_OBJECT:
                    array = JCSystem.makeTransientObjectArray(length, event);
                    break;
                case JCSystem.ARRAY_TYPE_INT:
                    SystemException.throwIt(SystemException.ILLEGAL_VALUE);
                    break;
                default:
                    SystemException.throwIt(SystemException.ILLEGAL_VALUE);
            }
        } else {
            SystemException.throwIt(SystemException.ILLEGAL_VALUE);
        }
        if (array != null) {
            Simulator.current().getTransientMemory().markSensitive(array);
        }
        return array;
    }
}
