// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.testapplets.testlib;

import javacard.framework.ISO7816;

public class TestLibrary {

    public static short valueHelper() {
        return ISO7816.SW_CLA_NOT_SUPPORTED;
    }
}
