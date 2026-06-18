// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import java.util.Set;

// The firewall ownership grain (JCRE 6.1.2): one package in 3.0.5, one CAP file (several packages)
// in 3.2. Two contexts are equal iff they own the same packages; one Context is minted per package,
// so value equality also coincides with reference identity.
public record Context(Set<EngineRegistryEntry> packages) {
    public static Context of(EngineRegistryEntry pkg) {
        return new Context(Set.of(pkg));
    }
}
