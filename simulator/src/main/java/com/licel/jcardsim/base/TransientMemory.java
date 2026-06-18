// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pro.javacard.engine.globalplatform.Context;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

// Manages transient, persistent, and sensitive memory
public final class TransientMemory {
    private static final Logger log = LoggerFactory.getLogger(TransientMemory.class);

    // CLEAR_ON_DESELECT arrays keyed by owning context (JCRE 5.1.2): deselecting one applet clears
    // only its context's arrays, never another's.
    private final Map<Context, List<Object>> clearOnDeselect = new HashMap<>();
    private final ArrayList<Object> clearOnReset = new ArrayList<>();
    private final ArrayList<Object> sensitive = new ArrayList<>(); // TODO: map of object to checksum
    private final ArrayList<Object> persistent = new ArrayList<>();

    private int sumCOD;
    private int sumCOR;
    private int sumPersistent;
    private int sumSensitive;

    // Registry of all allocated arrays (persistent and transient)
    // Key: Class Name -> Line Number -> List of arrays created/assigned there
    private final HashMap<String, HashMap<Integer, CopyOnWriteArrayList<WeakReference<Object>>>> allocations = new HashMap<>();

    public void registerAllocation(Object array, String className, int line) {
        if (array == null) {
            return;
        }

        // Normalize class name
        className = className.replace('/', '.');

        allocations.computeIfAbsent(className, k -> new HashMap<>())
                .computeIfAbsent(line, k -> new CopyOnWriteArrayList<>())
                .add(new WeakReference<>(array));
    }

    public Object getBuffer(String className, int line) {
        var classMap = allocations.get(className);
        if (classMap == null) {
            return null;
        }

        var list = classMap.get(line);
        if (list == null || list.isEmpty()) {
            return null;
        }

        // Return the last allocated/assigned buffer that is still alive
        for (int i = list.size() - 1; i >= 0; i--) {
            Object buf = list.get(i).get();
            if (buf != null) {
                return buf;
            }
        }
        return null;
    }

    // Compute "virtual size"
    private void add(Object obj, byte event) {
        int toAdd = 0;
        if (obj instanceof byte[] bytes) {
            toAdd += bytes.length;
        } else if (obj instanceof short[] shorts) {
            toAdd += shorts.length * 2;
        } else if (obj instanceof Object[] objects) {
            // Assume 16 bits for pointer. Arbitrary
            toAdd += objects.length * 2;
        } else if (obj instanceof boolean[] booleans) {
            toAdd += booleans.length;
        } else {
            log.warn("Unsupported object type: {}", obj.getClass());
        }

        if (event == JCSystem.MEMORY_TYPE_TRANSIENT_RESET) {
            sumCOR += toAdd;
        } else if (event == JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT) {
            sumCOD += toAdd;
        } else if (event == JCSystem.MEMORY_TYPE_PERSISTENT) {
            sumPersistent += toAdd;
        } else {
            log.warn("Unsupported memory type {}", event);
        }
    }

    /**
     * @param length the length of the array
     * @param event  the <code>CLEAR_ON...</code> event which causes the array elements to be cleared
     * @return the new transient array
     * @see javacard.framework.JCSystem#makeTransientBooleanArray(short, byte)
     */
    public boolean[] makeBooleanArray(short length, byte event, Context owner) {
        boolean[] array = new boolean[length];
        storeArray(array, event, owner);
        return array;
    }

    /**
     * @param length the length of the array
     * @param event  the <code>CLEAR_ON...</code> event which causes the array elements to be cleared
     * @return the new transient array
     * @see javacard.framework.JCSystem#makeTransientByteArray(short, byte)
     */
    public byte[] makeByteArray(int length, byte event, Context owner) {
        byte[] array = new byte[length];
        storeArray(array, event, owner);
        return array;
    }

    /**
     * @param length the length of the array
     * @param event  the <code>CLEAR_ON...</code> event which causes the array elements to be cleared
     * @return the new transient array
     * @see javacard.framework.JCSystem#makeTransientShortArray(short, byte)
     */
    public short[] makeShortArray(int length, byte event, Context owner) {
        short[] array = new short[length];
        storeArray(array, event, owner);
        return array;
    }

    /**
     * @param length the length of the array
     * @param event  the <code>CLEAR_ON...</code> event which causes the array elements to be cleared
     * @return the new transient array
     * @see javacard.framework.JCSystem#makeTransientObjectArray(short, byte)
     */
    public Object[] makeObjectArray(int length, byte event, Context owner) {
        Object[] array = new Object[length];
        storeArray(array, event, owner);
        return array;
    }

    /**
     * @param type   the array type - must be one of : ARRAY_TYPE_BOOLEAN, ARRAY_TYPE_BYTE, ARRAY_TYPE_SHORT, ARRAY_TYPE_INT, or ARRAY_TYPE_OBJECT
     * @param length the length of the global transient array
     * @return the new transient Object array
     * @see javacard.framework.JCSystem#makeGlobalArray(byte, short)
     */
    public Object makeGlobalArray(byte type, short length) {
        Object array = null;
        switch (type) {
            case JCSystem.ARRAY_TYPE_BOOLEAN:
                array = makeBooleanArray(length, JCSystem.CLEAR_ON_RESET, null);
                break;
            case JCSystem.ARRAY_TYPE_BYTE:
                array = makeByteArray(length, JCSystem.CLEAR_ON_RESET, null);
                break;
            case JCSystem.ARRAY_TYPE_SHORT:
                array = makeShortArray(length, JCSystem.CLEAR_ON_RESET, null);
                break;
            case JCSystem.ARRAY_TYPE_OBJECT:
                array = makeObjectArray(length, JCSystem.CLEAR_ON_RESET, null);
                break;
            case JCSystem.ARRAY_TYPE_INT:
                log.warn("int arrays not supported");
                SystemException.throwIt(SystemException.ILLEGAL_VALUE);
                break;
            default:
                SystemException.throwIt(SystemException.ILLEGAL_VALUE);
        }

        return array;
    }

    /**
     * @param theObj the object being queried
     * @return <code>NOT_A_TRANSIENT_OBJECT</code>, <code>CLEAR_ON_RESET</code>, or <code>CLEAR_ON_DESELECT</code>
     * @see javacard.framework.JCSystem#isTransient(Object)
     */
    public byte isTransient(Object theObj) {
        if (isClearOnDeselect(theObj)) {
            return JCSystem.CLEAR_ON_DESELECT;
        } else if (clearOnReset.contains(theObj)) {
            return JCSystem.CLEAR_ON_RESET;
        } else {
            return JCSystem.NOT_A_TRANSIENT_OBJECT;
        }
    }

    public boolean isSensitive(Object obj) {
        return sensitive.contains(obj);
    }

    public void markSensitive(Object obj) {
        if (!sensitive.contains(obj)) {
            sensitive.add(obj);
        }
    }

    /**
     * Store <code>arrayRef</code> in memory depends by event type
     *
     * @param arrayRef array reference
     * @param event    event type
     */
    private void storeArray(Object arrayRef, byte event, Context owner) {
        add(arrayRef, event);
        switch (event) {
            case JCSystem.CLEAR_ON_DESELECT:
                clearOnDeselect.computeIfAbsent(owner, k -> new ArrayList<>()).add(arrayRef);
                break;
            case JCSystem.CLEAR_ON_RESET:
                clearOnReset.add(arrayRef);
                break;
            case JCSystem.MEMORY_TYPE_PERSISTENT:
                persistent.add(arrayRef);
                break;
            default:
                SystemException.throwIt(SystemException.ILLEGAL_VALUE);
        }
    }

    // Zero one context's CLEAR_ON_DESELECT buffers (JCRE 5.1.2: applet deselected, no other applet
    // of the same context active).
    void clearOnDeselect(Context owner) {
        var arrays = clearOnDeselect.get(owner);
        if (arrays != null) {
            zero(arrays);
        }
    }

    // Zero every context's CLEAR_ON_DESELECT buffers (card reset implicitly deselects, JCRE 5.1.2).
    void clearOnDeselect() {
        for (var arrays : clearOnDeselect.values()) {
            zero(arrays);
        }
    }

    /**
     * Zero <code>CLEAR_ON_RESET</code> and <code>CLEAR_ON_DESELECT</code>
     * buffers
     */
    void clearOnReset() {
        clearOnDeselect();
        zero(clearOnReset);
    }

    private boolean isClearOnDeselect(Object theObj) {
        for (var arrays : clearOnDeselect.values()) {
            if (arrays.contains(theObj)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Zero all arrays in list
     *
     * @param list list of arrays
     */
    private void zero(List<Object> list) {
        for (Object obj : list) {
            if (obj instanceof byte[] bytes) {
                Arrays.fill(bytes, (byte) 0);
            } else if (obj instanceof short[] shorts) {
                Arrays.fill(shorts, (short) 0);
            } else if (obj instanceof Object[] objects) {
                Arrays.fill(objects, null);
            } else if (obj instanceof boolean[] booleans) {
                Arrays.fill(booleans, false);
            } else {
                log.warn("Unsupported object: {}", obj.getClass());
            }
        }
    }

    public int getSumCOD() {
        return sumCOD;
    }

    public int getSumCOR() {
        return sumCOR;
    }

    public int getSumPersistent() {
        return sumPersistent;
    }

    /**
     * @see javacard.framework.JCSystem#getAvailableMemory(byte)
     */
    public int getAvailableTransientResetMemory() {
        return Integer.MAX_VALUE - sumCOR;
    }

    /**
     * @see javacard.framework.JCSystem#getAvailableMemory(byte)
     */
    public int getAvailableTransientDeselectMemory() {
        return Integer.MAX_VALUE - sumCOD;
    }

    /**
     * @see javacard.framework.JCSystem#getAvailableMemory(byte)
     */
    public int getAvailablePersistentMemory() {
        return Integer.MAX_VALUE - sumPersistent;
    }

}
