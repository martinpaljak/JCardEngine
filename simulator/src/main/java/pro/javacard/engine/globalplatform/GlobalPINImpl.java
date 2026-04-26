// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import org.globalplatform.CVM;

import java.util.Arrays;

public class GlobalPINImpl implements CVM {

    private static final byte INACTIVE = 0x00;
    private static final byte ACTIVE = 0x01;
    private static final byte INVALID_SUBMISSION = 0x02;
    private static final byte VALIDATED = 0x03;
    private static final byte BLOCKED = 0x04;

    byte state = INACTIVE;
    byte format;
    byte[] value = null;
    byte try_counter = 0;
    byte try_limit = -1;


    @Override
    public boolean isActive() {
        return state > INACTIVE;
    }

    @Override
    public boolean isSubmitted() {
        return state == INVALID_SUBMISSION || state == VALIDATED;
    }

    @Override
    public boolean isVerified() {
        return state == VALIDATED;
    }

    @Override
    public boolean isBlocked() {
        return state == BLOCKED;
    }

    @Override
    public byte getTriesRemaining() {
        return try_counter;
    }

    @Override
    public boolean update(byte[] bytes, short i, byte b, byte b1) {
        if (b1 != CVM.FORMAT_HEX) {
            return false;
        }
        value = Arrays.copyOfRange(bytes, i, b);
        format = b1;
        if (try_limit > 0) {
            try_counter = try_limit;
            state = ACTIVE;
        }
        return true;
    }

    @Override
    public boolean resetState() {
        if (state > INACTIVE && state < BLOCKED) {
            state = ACTIVE;
            return true;
        }
        return false;
    }

    @Override
    public boolean blockState() {
        if (state > INACTIVE) {
            state = BLOCKED;
            return true;
        }
        return false;
    }

    @Override
    public boolean resetAndUnblockState() {
        if (state > INACTIVE) {
            state = ACTIVE;
        }
        return false;
    }

    @Override
    public boolean setTryLimit(byte b) {
        if (b > 0) {
            try_limit = b;
            if (value != null) {
                state = ACTIVE;
            }
            return true;
        }
        return false;
    }

    @Override
    public short verify(byte[] bytes, short i, byte b, byte b1) {
        if (isBlocked() || !isActive()) {
            return CVM.CVM_FAILURE;
        }

        if (b1 == format && Arrays.equals(value, Arrays.copyOfRange(bytes, i, b))) {
            try_counter = try_limit;
            state = VALIDATED;
            return CVM_SUCCESS;
        }

        state = INVALID_SUBMISSION;
        if (--try_counter == 0) {
            state = BLOCKED;
        }
        return CVM.CVM_FAILURE;
    }
}
