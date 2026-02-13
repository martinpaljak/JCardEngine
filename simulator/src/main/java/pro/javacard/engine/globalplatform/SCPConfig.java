/*
 * Copyright 2025 Martin Paljak <martin@martinpaljak.net>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
