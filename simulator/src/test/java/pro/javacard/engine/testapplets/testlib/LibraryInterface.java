// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.testapplets.testlib;

import javacard.framework.Shareable;

public interface LibraryInterface extends Shareable {
    short getValue();
}
