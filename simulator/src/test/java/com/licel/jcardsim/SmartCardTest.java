package com.licel.jcardsim;

import org.opentest4j.AssertionFailedError;
import org.opentest4j.ValueWrapper;

public interface SmartCardTest {

    static String sw(int v) {
        return String.format("0x%04X", v);
    }

    default void assertSW(int expected, int actual) throws AssertionFailedError {
        if (expected != actual)
            throw new AssertionFailedError(String.format("Smart card error: %s != %s", sw(actual), sw(expected)), ValueWrapper.create(expected, sw(expected)), ValueWrapper.create(actual, sw(actual)));
    }
}
