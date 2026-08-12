// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import apdu4j.core.CommandAPDU;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.gp.GPRegistryEntry.Privilege;

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

    // SELECT [by name] is processed by the OPEN (GPC v2.3.1 6.3): resolve the target Application from
    // the registry. Case 1/2 (no data) selects the ISD; otherwise full-AID then partial-AID match. ELFs
    // (Kind.PKG) are never selectable (GPC v2.3.1 6.5.1.1), so getApplets() already excludes them. Null on miss.
    // For [next occurrence] (GPC v2.3.1 6.4.2.1.2) the search resumes after the currently selected Application
    // (current), so a client can walk multiple partial matches; [first or only occurrence] starts from the start.
    // A LOCKED Application is not a valid by-name target (GPC v2.3.1 6.4.2.1.2): skip it and keep searching.
    public static EngineRegistryEntry findAppletForSelectApdu(GlobalPlatformEngine gp, CommandAPDU select,
                                                              EngineRegistryEntry current, boolean nextOccurrence) {
        if (select.getNc() == 0) {
            // No data: select the ISD via the stable reference (its AID may have been re-keyed).
            log.info("Selecting OPEN");
            return gp.isd();
        }
        final byte[] aid = select.getData();
        final byte lc = (byte) aid.length;
        if (nextOccurrence) {
            // Single ordered pass over the entries following current, returning the next full or partial match.
            boolean afterCurrent = current == null;
            for (var e : gp.getApplets()) {
                if (!afterCurrent) {
                    afterCurrent = e == current;
                    continue;
                }
                if (e.isLocked()) {
                    continue;
                }
                if (!e.getAID().partialEquals(aid, (short) 0, lc)) {
                    continue;
                }
                log.trace("Selecting next occurrence: {}", e.getAID());
                return e;
            }
            return null;
        }
        for (var e : gp.getApplets()) {
            if (e.isLocked()) {
                continue;
            }
            if (!e.getAID().equals(aid, (short) 0, lc)) {
                continue;
            }
            log.trace("Selecting on full AID match: {}", e.getAID());
            return e;
        }
        for (var e : gp.getApplets()) {
            if (e.isLocked()) {
                continue;
            }
            if (!e.getAID().partialEquals(aid, (short) 0, lc)) {
                continue;
            }
            log.trace("Selecting on partial AID match: {}", e.getAID());
            return e;
        }
        return null;
    }

    // GPC v2.3.1 6.4.1 / 6.4.2.1.1: the CardReset-privilege holder is the implicitly selected Application.
    public static EngineRegistryEntry implicitlySelectedEntry(GlobalPlatformEngine gp) {
        return findHolder(gp, Privilege.CardReset).orElseThrow();
    }
}
