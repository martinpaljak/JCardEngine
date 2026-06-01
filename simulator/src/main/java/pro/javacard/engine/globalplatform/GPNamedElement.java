// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import pro.javacard.tlv.Tag;

// A GP entity identified by a symbolic name. The data a member carries lives per-owner in the
// registry entry's map, not on the element. A record `name` component satisfies name() with no extra code.
public sealed interface GPNamedElement permits GPNamedElement.GPTag, GPNamedElement.GPInfo {
    String name();

    // A BER-TLV data object identified by a Tag. The value lives per-owner in the byte[] store keyed by this element.
    record GPTag(String name, Tag tag) implements GPNamedElement {
    }

    // A Contactless Application Information element (GPC v2.3.1 Amd C 11.2.3). event is the CLAppletEvent
    // raised on a value change (GPC v2.3.1 Amd C 3.10.2: a User Interaction parameter update notifies CREL/CRS).
    record GPInfo(String name, short info, Tag tag, short event) implements GPNamedElement {
    }
}
