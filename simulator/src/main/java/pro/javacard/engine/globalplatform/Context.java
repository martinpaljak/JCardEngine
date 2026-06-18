// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import java.util.Set;

// The firewall ownership grain (JCRE 6.1.2): one package in 3.0.5, one CAP file (several packages)
// in 3.2. Compared by reference identity (==), keyed in IdentityHashMap, never by value.
public record Context(Set<EngineRegistryEntry> packages) {
    public static Context of(EngineRegistryEntry pkg) {
        return new Context(Set.of(pkg));
    }
}
