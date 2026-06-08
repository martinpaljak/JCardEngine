// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import org.globalplatform.contactless.CLAppletEvent;
import org.globalplatform.contactless.GPCLRegistryEntry;

import java.util.Optional;

// CL activation states (GPC v2.3.1 Amd C): byte encoding + the event raised on transition.
public enum CLState {
    DEACTIVATED(GPCLRegistryEntry.STATE_CL_DEACTIVATED, CLAppletEvent.EVENT_DEACTIVATED),
    ACTIVATED(GPCLRegistryEntry.STATE_CL_ACTIVATED, CLAppletEvent.EVENT_ACTIVATED),
    NON_ACTIVATABLE(GPCLRegistryEntry.STATE_CL_NON_ACTIVATABLE, CLAppletEvent.EVENT_NON_ACTIVATABLE);

    public final byte value;
    public final short event;

    CLState(byte value, short event) {
        this.value = value;
        this.event = event;
    }

    public static Optional<CLState> ofByte(byte b) {
        for (var s : values()) {
            if (s.value == b) {
                return Optional.of(s);
            }
        }
        return Optional.empty();
    }

    // Parse the Initial Contactless Activation State byte (INSTALL tag 81). GPC v2.3.1 Amd C 8.3 permits
    // only 0x00 (DEACTIVATED) or 0x01 (ACTIVATED); NON_ACTIVATABLE (0x80) is a runtime state, not an initial value.
    public static CLState parse(byte[] v) {
        if (v.length != 1) {
            throw new IllegalArgumentException("CL state must be 1 byte, got " + v.length);
        }
        return ofByte(v[0]).filter(s -> s != NON_ACTIVATABLE).orElseThrow(() -> new IllegalArgumentException(
                "Initial CL activation state must be 0x00 or 0x01; got 0x%02X".formatted(v[0] & 0xFF)));
    }
}
