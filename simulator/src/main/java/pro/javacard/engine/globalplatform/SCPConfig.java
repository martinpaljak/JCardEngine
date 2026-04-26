// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import pro.javacard.gp.keys.PlaintextKeys;

public sealed interface SCPConfig permits SCPConfig.SCP02, SCPConfig.SCP03 {
    record SCP02(byte[] masterKey) implements SCPConfig {
        public SCP02 {
            masterKey = masterKey.clone();
        }

        public SCP02() {
            this(PlaintextKeys.DEFAULT_KEY());
        }

        @Override
        public byte[] masterKey() {
            return masterKey.clone();
        }
    }

    record SCP03(byte[] masterKey, boolean s16) implements SCPConfig {
        public SCP03 {
            masterKey = masterKey.clone();
        }

        public SCP03() {
            this(PlaintextKeys.DEFAULT_KEY(), false);
        }

        public SCP03(byte[] key) {
            this(key, false);
        }

        public SCP03(boolean s16) {
            this(PlaintextKeys.DEFAULT_KEY(), s16);
        }

        @Override
        public byte[] masterKey() {
            return masterKey.clone();
        }
    }
}
