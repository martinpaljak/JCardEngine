// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import com.licel.jcardsim.base.Simulator;
import org.globalplatform.CVM;
import org.globalplatform.GPRegistryEntry;

import java.util.Arrays;

public class EngineGlobalPIN implements CVM {

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

    // GPC v2.3.1 6.6.1 (Table 6-1, CVM Management privilege) + 8.2.1: update/blockState/
    // resetAndUnblockState/setTryLimit are gated on PRIVILEGE_CVM_MANAGEMENT held by the
    // current applet context.
    private static boolean callerHasCvmManagement() {
        var caller = Simulator.current().caller();
        return caller != null && caller.isPrivileged(GPRegistryEntry.PRIVILEGE_CVM_MANAGEMENT);
    }

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
        if (!callerHasCvmManagement()) {
            return false;
        }
        if (b1 != CVM.FORMAT_HEX) {
            return false;
        }
        int len = b & 0xFF;
        value = Arrays.copyOfRange(bytes, i, i + len);
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
        if (!callerHasCvmManagement()) {
            return false;
        }
        if (state > INACTIVE) {
            state = BLOCKED;
            return true;
        }
        return false;
    }

    @Override
    public boolean resetAndUnblockState() {
        if (!callerHasCvmManagement()) {
            return false;
        }
        if (state == INACTIVE) {
            return false;
        }
        state = ACTIVE;
        try_counter = try_limit;
        return true;
    }

    @Override
    public boolean setTryLimit(byte b) {
        if (!callerHasCvmManagement()) {
            return false;
        }
        if (b > 0) {
            try_limit = b;
            try_counter = b;
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

        int len = b & 0xFF;
        if (b1 == format && Arrays.equals(value, Arrays.copyOfRange(bytes, i, i + len))) {
            try_counter = try_limit;
            state = VALIDATED;
            return CVM_SUCCESS;
        }

        state = INVALID_SUBMISSION;
        if (--try_counter <= 0) {
            state = BLOCKED;
        }
        return CVM.CVM_FAILURE;
    }

    // GPC v2.3.1 8.2.2.2.1: at end of Card Session the CVM transitions back to ACTIVE, preserving the
    // retry counter. BLOCKED survives across sessions; INACTIVE (never initialized) stays put.
    //
    // The simulator cannot observe end-of-session directly (no card-removal event), but the next
    // power-up arrives as reset() - logically equivalent, since nothing observable happens between
    // session end and the following power-up. Same model as CLEAR_ON_RESET transient memory: we
    // always act on reset.
    void onCardReset() {
        if (state != BLOCKED && state != INACTIVE) {
            state = ACTIVE;
        }
    }
}
