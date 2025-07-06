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

import org.globalplatform.CVM;

public class GlobalPINImpl implements CVM {

    public static boolean submitted = false;
    public static boolean verified = false;
    public static boolean active = false;

    @Override
    public boolean isActive() {
        return active;
    }

    @Override
    public boolean isSubmitted() {
        return submitted;
    }

    @Override
    public boolean isVerified() {
        return verified;
    }

    @Override
    public boolean isBlocked() {
        return false;
    }

    @Override
    public byte getTriesRemaining() {
        return 0;
    }

    @Override
    public boolean update(byte[] bytes, short i, byte b, byte b1) {
        return false;
    }

    @Override
    public boolean resetState() {
        return false;
    }

    @Override
    public boolean blockState() {
        return false;
    }

    @Override
    public boolean resetAndUnblockState() {
        return false;
    }

    @Override
    public boolean setTryLimit(byte b) {
        return false;
    }

    @Override
    public short verify(byte[] bytes, short i, byte b, byte b1) {
        return 0;
    }
}
