// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import apdu4j.core.CommandAPDU;
import org.globalplatform.contactless.GPCLRegistryEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.gp.GPRegistryEntry.Privilege;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

// Stateless OPEN registry policy: single-holder privilege invariants and SELECT/AID resolution.
// Pure functions over the engine's registry - the GlobalPlatformEngine is passed in, nothing is held.
public final class RegistryPolicy {
    private static final Logger log = LoggerFactory.getLogger(RegistryPolicy.class);

    private RegistryPolicy() {
    }

    // The single current holder of priv, if any.
    // @throws IllegalStateException when more than one entry holds it (broken invariant).
    public static Optional<EngineRegistryEntry> findHolder(GlobalPlatformEngine gp, Privilege priv) {
        EngineRegistryEntry found = null;
        for (var e : gp.getApplets()) {
            if (e.getPrivileges().contains(priv)) {
                if (found != null) {
                    throw new IllegalStateException("Multiple holders of " + priv);
                }
                found = e;
            }
        }
        return Optional.ofNullable(found);
    }

    static void stripFromOthers(GlobalPlatformEngine gp, EngineRegistryEntry keep, Privilege priv) {
        for (var e : gp.getApplets()) {
            if (e != keep && e.getPrivileges().contains(priv)) {
                var p = e.getPrivileges();
                p.remove(priv);
                e.setPrivileges(p);
                log.info("Stripped {} from {}", priv, e.getAID());
            }
        }
    }

    static void grant(EngineRegistryEntry target, Privilege priv) {
        var p = target.getPrivileges();
        p.add(priv);
        target.setPrivileges(p);
        log.info("Granted {} to {}", priv, target.getAID());
    }

    // SELECT [by name] is processed by the OPEN (GPC v2.3.1 6.3): every selectable full or partial match,
    // in registry order. Case 1/2 (no data) selects the ISD; ELFs (Kind.PKG) are never selectable
    // (GPC v2.3.1 6.5.1.1), so getApplets() already excludes them. An INSTALLED or LOCKED Application is
    // not a valid by-name target (GPC v2.3.1 6.4.2.1.2). [next occurrence] resumes after the currently
    // selected Application (current); [first or only occurrence] starts from the start of the registry.
    public static List<EngineRegistryEntry> findSelectCandidates(GlobalPlatformEngine gp, CommandAPDU select,
                                                                 EngineRegistryEntry current, boolean nextOccurrence, boolean contactless) {
        if (select.getNc() == 0) {
            // No data: select the ISD via the stable reference (its AID may have been re-keyed).
            log.info("Selecting OPEN");
            return List.of(gp.isd());
        }
        final byte[] aid = select.getData();
        // A search string that is not an AID (ISO 7816-5: 5..16 bytes) matches nothing.
        if (aid.length < 5 || aid.length > 16) {
            log.warn("Not an AID: {} bytes", aid.length);
            return List.of();
        }
        final var candidates = new ArrayList<EngineRegistryEntry>();
        boolean afterCurrent = !nextOccurrence || current == null;
        // The registry is AID-ordered, so a full match precedes every AID extending it: one pass suffices.
        for (var e : gp.getApplets()) {
            if (!afterCurrent) {
                afterCurrent = e == current;
                continue;
            }
            if (!e.isSelectable()) {
                continue;
            }
            // GPC v2.3.1 Amd C 6.3.1: over the contactless interface only an ACTIVATED Application is a candidate.
            if (contactless && e.internalGetCLState() != GPCLRegistryEntry.STATE_CL_ACTIVATED) {
                continue;
            }
            if (!e.getAID().partialEquals(aid, (short) 0, (byte) aid.length)) {
                continue;
            }
            log.trace("Selection candidate: {}", e.getAID());
            candidates.add(e);
        }
        return candidates;
    }

    // GPC v2.3.1 6.4.1 / 6.4.2.1.1: the CardReset-privilege holder is the implicitly selected Application.
    public static EngineRegistryEntry implicitlySelectedEntry(GlobalPlatformEngine gp) {
        return findHolder(gp, Privilege.CardReset).orElseThrow();
    }
}
