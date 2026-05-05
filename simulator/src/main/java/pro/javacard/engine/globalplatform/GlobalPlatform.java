// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Applet;
import org.bouncycastle.util.encoders.Hex;
import org.globalplatform.CVM;
import org.globalplatform.GPRegistryEntry;
import org.globalplatform.GPSystem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.engine.JavaCardEngineException;
import pro.javacard.gp.GPRegistryEntry.Kind;

import java.util.Collection;
import java.util.Collections;
import java.util.SortedMap;
import java.util.TreeMap;

public class GlobalPlatform {
    private static final Logger log = LoggerFactory.getLogger(GlobalPlatform.class);
    private final EngineSecureChannel sc;
    private final SCPConfig scpConfig;
    private final EngineGlobalPIN gpin = new EngineGlobalPIN();

    // CPLC value (ISO/IEC 7816-6 tag '9F7F', Visa GP convention; not in GPC). 42 bytes.
    // Card-wide and mostly factory-fixed; only the perso slice (bytes 34..41) and pre-perso
    // slice (bytes 26..33) are mutable, via STORE DATA tags 9F66 / 9F67 routed through the ISD —
    // SecurityDomainApplet validates and writes those slices directly. Bytes 10..17 feed
    // SCP02/SCP03 KDD derivation in EngineSecureChannel.sessionKDD().
    // Layout: [0..1] IC fabricator '4242' (engine signature), [10..11] IC fab date '4242',
    // [12..15] IC SN 'JCEN' (readable engine marker), [16..17] IC batch ID '4242', rest zero.
    final byte[] cplc = Hex.decode("4242000000000000000042424A43454E4242000000000000000000000000000000000000000000000000");

    // Registry of load files (Kind.PKG). Tracked separately since a load file AID may coincide
    // with an applet instance AID (test convenience `sim.loadApplet(aid, aid, klass)`), which
    // would otherwise collide in a single-keyed map.
    private final SortedMap<AID, EngineRegistryEntry> packages = new TreeMap<>(AIDUtil.comparator());

    public GlobalPlatform(SCPConfig scpConfig) {
        if (scpConfig == null) {
            scpConfig = new SCPConfig.SCP03(true);
        }
        this.scpConfig = scpConfig;
        if (scpConfig instanceof SCPConfig.SCP02) {
            sc = new SCP02SecureChannelImpl();
        } else if (scpConfig instanceof SCPConfig.SCP03 c) {
            sc = new SCP03SecureChannelImpl(c.s16());
        } else {
            throw new IllegalArgumentException("Unsupported SCP config: " + scpConfig);
        }
    }

    public GlobalPlatform() {
        this(null);
    }

    // Virtual load entry point. Real GP would do INSTALL [for load] (associates the ELF with the
    // issuing SD) followed by LOAD blocks; the engine collapses both into one call but still
    // honours the SD association — the PKG entry's associated SD is set on first load.
    public void loadClass(AID packageAid, AID appletAid, Class<? extends Applet> appletClass, AID associatedSD) {
        String pkgname = appletClass.getPackageName();

        // Locate an existing PKG entry by Java package name OR by package AID
        EngineRegistryEntry pkg = null;
        for (var entry : packages.values()) {
            if (pkgname.equals(entry.getJavaPackageName()) || entry.getAID().equals(packageAid)) {
                log.debug("Matching package entry: {}", entry);
                pkg = entry;
                break;
            }
        }
        if (pkg == null) {
            pkg = EngineRegistryEntry.forPackage(packageAid, pkgname, associatedSD);
            packages.put(packageAid, pkg);
        }

        if (pkg.getModules().containsKey(appletAid)) {
            log.error("Applet already present");
            throw new JavaCardEngineException("Applet already loaded");
        }

        pkg.addModule(appletAid, appletClass);
        log.info("Loaded applet {}", appletClass.getCanonicalName());
    }

    // Plant a built-in load file entry. Used at engine boot to register the SD code as a load file
    // that callers can target via INSTALL [for install]. javaPackageName is null so loadClass()
    // will not accidentally merge user-loaded classes that share a Java package name with this entry.
    // Built-in packages are associated with the ISD — they are platform-provided, not user-loaded.
    public void addBuiltinPackage(AID packageAid, AID moduleAid, Class<? extends Applet> moduleClass) {
        var existing = packages.get(packageAid);
        if (existing != null) {
            throw new IllegalStateException("Builtin package already registered: " + AIDUtil.toString(packageAid));
        }
        var pkg = EngineRegistryEntry.forPackage(packageAid, null, SecurityDomainApplet.OPEN_AID);
        pkg.addModule(moduleAid, moduleClass);
        packages.put(packageAid, pkg);
    }

    // Plant the ISD entry directly: the OPEN is an override, not a normal install.
    // Structural plant of the factory KVN (0xFF) keyset matching the SCP type;
    // bypasses the personalization-only factory trigger that putKey applies.
    public void bootstrap(SortedMap<AID, EngineRegistryEntry> registry) {
        if (registry.containsKey(SecurityDomainApplet.OPEN_AID)) {
            return;
        }
        var isd = new SecurityDomainApplet();
        isd.seedKey(bootstrapKeySet());
        var entry = EngineRegistryEntry.forISD(SecurityDomainApplet.OPEN_AID, isd, true,
                SecurityDomainApplet.ISD_DEFAULT_PRIVILEGES, SecurityDomainApplet.SSD_PACKAGE_AID);
        registry.put(SecurityDomainApplet.OPEN_AID, entry);
        addBuiltinPackage(SecurityDomainApplet.SSD_PACKAGE_AID, SecurityDomainApplet.SSD_MODULE_AID, SecurityDomainApplet.class);
    }

    private KeySet bootstrapKeySet() {
        if (scpConfig instanceof SCPConfig.SCP02 c) {
            return KeySet.ofMaster(SecurityDomainApplet.FACTORY_KVN, KeySet.TYPE_DES3, c.masterKey());
        }
        if (scpConfig instanceof SCPConfig.SCP03 c) {
            return KeySet.ofMaster(SecurityDomainApplet.FACTORY_KVN, KeySet.TYPE_AES, c.masterKey());
        }
        throw new IllegalStateException("Unsupported SCP config: " + scpConfig);
    }

    public Collection<EngineRegistryEntry> getPackages() {
        return Collections.unmodifiableCollection(packages.values());
    }

    public EngineRegistryEntry getPackage(AID packageAid) {
        return packages.get(packageAid);
    }

    public Class<? extends Applet> locateApplet(AID packageAid, AID appletAid) {
        for (var entry : packages.values()) {
            if (entry.getAID().equals(packageAid)) {
                log.debug("Matched package {} by {}", entry.getJavaPackageName(), entry.getAID());
                var c = entry.getModules().get(appletAid);
                if (c != null) {
                    log.debug("Found applet {} in pkg {}", appletAid, entry.getJavaPackageName());
                    return c;
                }
            }
        }
        log.warn("pkg {} / applet {} not found in registry.", packageAid, appletAid);
        return null;
    }

    /**
     * Resolve a registry entry by AID. {@code null} means the caller's own entry.
     * Cross-applet lookups require the GlobalRegistry privilege; system context
     * (no current applet) bypasses the gate. Falls back to PKG entries when an
     * applet lookup misses.
     */
    public GPRegistryEntry getRegistryEntry(AID aid) {
        var sim = Simulator.current();
        AID callerAID = sim.getAID();

        // System context (no current applet) bypasses the gate entirely.
        if (callerAID == null) {
            if (aid == null) {
                return null;
            }
            var entry = sim.lookupApplet(aid);
            return entry != null ? entry : packages.get(aid);
        }

        // null target resolves to the caller's own entry.
        if (aid == null || callerAID.equals(aid)) {
            return sim.lookupApplet(callerAID);
        }

        // Cross-applet lookup requires GlobalRegistry privilege.
        var callerEntry = sim.lookupApplet(callerAID);
        if (callerEntry == null || !callerEntry.isPrivileged(GPRegistryEntry.PRIVILEGE_GLOBAL_REGISTRY)) {
            log.warn("Application {} denied getRegistryEntry({}): GlobalRegistry privilege required",
                    AIDUtil.toString(callerAID), AIDUtil.toString(aid));
            return null;
        }

        return sim.lookupApplet(aid);
    }

    public EngineSecureChannel getSecureChannel() {
        return sc;
    }

    public void reset() {
        sc.resetSecurity();
        gpin.onCardReset();
    }

    public CVM getGlobalPIN() {
        return gpin;
    }

    public byte getCardState() {
        var isd = Simulator.current().lookupApplet(SecurityDomainApplet.OPEN_AID);
        return isd == null ? GPSystem.CARD_OP_READY : isd.getState();
    }

    public boolean lockCard() {
        return setCardLifecycleState(GPSystem.CARD_LOCKED);
    }

    public boolean terminateCard() {
        return setCardLifecycleState(GPSystem.CARD_TERMINATED);
    }

    public boolean setCardLifecycleState(byte newState) {
        var sim = Simulator.current();
        AID callerAID = sim.getAID();
        if (callerAID == null) {
            return false; // system context: no caller to authorize
        }
        var caller = sim.lookupApplet(callerAID);
        if (caller == null) {
            return false;
        }
        var isd = sim.lookupApplet(SecurityDomainApplet.OPEN_AID);
        if (isd == null) {
            return false;
        }
        byte current = isd.getState();

        boolean allowed = switch (newState) {
            // Pre-issuance, irreversible (GPC v2.3.1 5.1.1.2 / 5.1.1.3). Authorized via Authorized
            // Management privilege — held by the ISD by default, so SET STATUS over SCP works.
            case GPSystem.CARD_INITIALIZED ->
                    current == GPSystem.CARD_OP_READY
                            && caller.isPrivileged(GPRegistryEntry.PRIVILEGE_AUTHORIZED_MANAGEMENT);
            case GPSystem.CARD_SECURED ->
                    (current == GPSystem.CARD_INITIALIZED
                            && caller.isPrivileged(GPRegistryEntry.PRIVILEGE_AUTHORIZED_MANAGEMENT))
                            // Unlock target from CARD_LOCKED (GPC v2.3.1 5.1.1.4, reversible).
                            || (current == GPSystem.CARD_LOCKED
                            && caller.isPrivileged(GPRegistryEntry.PRIVILEGE_CARD_LOCK));
            // Post-issuance, reversible (GPC v2.3.1 5.1.1.4).
            case GPSystem.CARD_LOCKED ->
                    current == GPSystem.CARD_SECURED
                            && caller.isPrivileged(GPRegistryEntry.PRIVILEGE_CARD_LOCK);
            // Terminal state (GPC v2.3.1 5.1.1.5), irreversible from any other state.
            case GPSystem.CARD_TERMINATED ->
                    current != GPSystem.CARD_TERMINATED
                            && caller.isPrivileged(GPRegistryEntry.PRIVILEGE_CARD_TERMINATE);
            default -> false;   // OP_READY isn't a target — there's no transition into it.
        };
        if (!allowed) {
            return false;
        }
        isd.internalForceState(newState);
        return true;
    }

    // GP API GPSystem.setCardContentState (export file v1.8) — the legacy self-only shortcut
    // for an Application to update its own Life Cycle State. Adds two pre-conditions on top of
    // the general GPRegistryEntry.setState path: the caller must currently be in an
    // application-specific state (0x07..0x7F with the 3 low order bits set, i.e. SELECTABLE or
    // beyond and not LOCKED), and the new state must be either application-specific or have
    // its high order bit set to request a self-lock. Self-unlock is explicitly forbidden by
    // the API contract. After the pre-conditions pass, the actual mutation and the irreversibility
    // / privilege rules are delegated to caller.setState which is the canonical authority.
    public boolean setCardContentState(byte newState) {
        var sim = Simulator.current();
        AID callerAID = sim.getAID();
        if (callerAID == null) {
            return false;
        }
        var caller = sim.lookupApplet(callerAID);
        if (caller == null) {
            return false;
        }
        int current = caller.getState() & 0xFF;
        if (current < 0x07 || current > 0x7F || (current & 0x07) != 0x07) {
            return false;
        }
        int next = newState & 0xFF;
        boolean newAppSpecific = next >= 0x07 && next <= 0x7F && (next & 0x07) == 0x07;
        boolean newLocked = (newState & (byte) 0x80) != 0;
        if (!newAppSpecific && !newLocked) {
            return false;
        }
        return caller.setState(newState);
    }
}
