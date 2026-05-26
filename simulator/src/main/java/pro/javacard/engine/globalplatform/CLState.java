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

    // Parse a 1-byte CL state value (e.g. INSTALL tag 81). Throws on bad length or unknown value.
    public static CLState parse(byte[] v) {
        if (v.length != 1) {
            throw new IllegalArgumentException("CL state must be 1 byte, got " + v.length);
        }
        return ofByte(v[0]).orElseThrow(() -> new IllegalArgumentException(
                "CL state must be 0x00 / 0x01 / 0x80; got 0x%02X".formatted(v[0] & 0xFF)));
    }
}
