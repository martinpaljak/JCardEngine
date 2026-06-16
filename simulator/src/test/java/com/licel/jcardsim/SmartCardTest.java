// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim;

public interface SmartCardTest {

    static String sw(int v) {
        return String.format("0x%04X", v);
    }

    default void assertSW(int expected, int actual) throws AssertionError {
        if (expected != actual) {
            throw new AssertionError(String.format("Smart card error: %s != %s", sw(actual), sw(expected)));
        }
    }
}
