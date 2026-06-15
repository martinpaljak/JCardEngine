// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2022 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

enum CipherState {
    UNINITIALIZED,
    INITIALIZED,
    FINALIZED;

    // FINALIZED counts as initialized: the cipher was init'd, then ran to completion.
    boolean initialized() {
        return this != UNINITIALIZED;
    }
}
