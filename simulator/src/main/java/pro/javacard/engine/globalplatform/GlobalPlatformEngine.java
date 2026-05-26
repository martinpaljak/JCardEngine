// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Applet;
import org.globalplatform.CVM;
import org.globalplatform.GPRegistryEntry;
import org.globalplatform.GPSystem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.engine.JavaCardEngineException;
import pro.javacard.gp.GPRegistryEntry.Kind;
import pro.javacard.gp.GPRegistryEntry.Privilege;

import java.util.*;

public class GlobalPlatformEngine {
    private static final Logger log = LoggerFactory.getLogger(GlobalPlatformEngine.class);
    private final EngineSecureChannel sc;
    private final EngineGlobalPIN gpin = new EngineGlobalPIN();

    // THE registry
    private final SortedMap<AID, EngineRegistryEntry> registry = new TreeMap<>(AIDUtil.comparator());

    // THE ISD
    private final EngineRegistryEntry isd;

    // GPC CL Global Update Counter
    private int updateCounter = 0;

    public GlobalPlatformEngine(SCPConfig scpConfig) {
        Objects.requireNonNull(scpConfig, "GlobalPlatform requires an SCP configuration");
        KeySet factoryKeys;
        if (scpConfig instanceof SCPConfig.SCP02 c) {
            sc = new SCP02SecureChannel();
            factoryKeys = KeySet.ofMaster(SecurityDomainApplet.FACTORY_KVN, KeySet.TYPE_DES3, c.masterKey());
        } else if (scpConfig instanceof SCPConfig.SCP03 c) {
            sc = new SCP03SecureChannel(c.s16());
            factoryKeys = KeySet.ofMaster(SecurityDomainApplet.FACTORY_KVN, KeySet.TYPE_AES, c.masterKey());
        } else {
            throw new IllegalArgumentException("Unsupported SCP config: " + scpConfig);
        }
        // The ISD is bootstrapped directly with the factory KVN (0xFF) keyset, bypassing putKey.
        var isdApplet = new SecurityDomainApplet(factoryKeys);
        isd = EngineRegistryEntry.forISD(SecurityDomainApplet.OPEN_AID, isdApplet, SecurityDomainApplet.SSD_PACKAGE_AID);
        registry.put(SecurityDomainApplet.OPEN_AID, isd);
        // CPLC (9F7F) is card-wide: seed the default into the ISD's data store as a usual tag.
        isd.putData(GPData.CPLC, SecurityDomainApplet.DEFAULT_CPLC);
        addBuiltinPackage(SecurityDomainApplet.SSD_PACKAGE_AID, SecurityDomainApplet.SSD_MODULE_AID, SecurityDomainApplet.class);
    }

    // Virtual load: collapses INSTALL [for load] + LOAD blocks into one call. Associated SD set on first load.
    public void loadClass(AID packageAid, AID appletAid, Class<? extends Applet> appletClass, AID associatedSD) {
        String pkgname = appletClass.getPackageName();

        // Locate existing PKG by Java package name or package AID.
        EngineRegistryEntry pkg = null;
        for (var entry : registry.values()) {
            if (entry.getKind() == Kind.PKG && (pkgname.equals(entry.getJavaPackageName()) || entry.getAID().equals(packageAid))) {
                log.debug("Matching package entry: {}", entry);
                pkg = entry;
                break;
            }
        }
        if (pkg == null) {
            pkg = EngineRegistryEntry.forPackage(packageAid, pkgname, lookup(associatedSD));
            registry.put(packageAid, pkg);
        }

        if (pkg.getModules().containsKey(appletAid)) {
            log.error("Applet already present");
            throw new JavaCardEngineException("Applet already loaded");
        }

        pkg.addModule(appletAid, appletClass);
        log.info("Loaded applet {}", appletClass.getCanonicalName());
    }

    // Register a built-in load file at boot (e.g. SD code) targetable via INSTALL [for install].
    public void addBuiltinPackage(AID packageAid, AID moduleAid, Class<? extends Applet> moduleClass) {
        if (registry.get(packageAid) != null) {
            throw new IllegalStateException("Builtin package already registered: " + packageAid);
        }
        var pkg = EngineRegistryEntry.forPackage(packageAid, null, isd);
        pkg.addModule(moduleAid, moduleClass);
        registry.put(packageAid, pkg);
    }

    // Register the default CRS applet. Deferred out of the constructor because EngineCRSApplet
    // allocates transient arrays via JCSystem and so needs the Simulator to be current; build() calls
    // this inside asCurrent().
    public void bootstrap() {
        var crsEntry = EngineRegistryEntry.forApplet(EngineCRSApplet.CRS_AID, new EngineCRSApplet(), true,
                EnumSet.of(Privilege.ContactlessActivation, Privilege.GlobalRegistry), EngineCRSApplet.CRS_PACKAGE_AID, isd);
        registry.put(EngineCRSApplet.CRS_AID, crsEntry);
        addBuiltinPackage(EngineCRSApplet.CRS_PACKAGE_AID, EngineCRSApplet.CRS_AID, EngineCRSApplet.class);
    }

    public EngineRegistryEntry isd() {
        return isd;
    }

    // Resolve any entry by AID (ELFs included); callers needing selectable applets filter Kind.PKG.
    public EngineRegistryEntry lookup(AID lookupAid) {
        log.trace("Searching registry for {}", lookupAid);
        var entry = registry.get(lookupAid);
        if (entry == null) {
            log.warn("Application not found: {}", lookupAid);
        }
        return entry;
    }

    // Build the APP/SSD entry from install materials and land it in the registry.
    public void register(AID aid, Object instance, boolean exposed, byte[] privileges, AID packageAID, AID parentSD) {
        // GPC v2.3.1 9.3.6: an Application inherits the associated SD of the ELF it is installed from.
        // The no-ELF direct path (host-side install) falls back to the supplied issuing SD.
        var elf = lookup(packageAID);
        var parent = elf != null ? elf.getParentSD() : lookup(parentSD);
        var entry = EngineRegistryEntry.forApplet(aid, instance, exposed, privileges, packageAID, parent);
        // GPC v2.3.1 6.6.2: Card Reset is single-holder.
        if (entry.getPrivileges().contains(Privilege.CardReset)) {
            RegistryPolicy.stripFromOthers(this, entry, Privilege.CardReset);
        }
        // GPC v2.3.1 6.6.2: Final Application is single-holder.
        if (entry.getPrivileges().contains(Privilege.FinalApplication)) {
            RegistryPolicy.stripFromOthers(this, entry, Privilege.FinalApplication);
        }
        // GPC v2.3.1 Amd C 7.1: Contactless Activation is single-holder (the CRS role is transferable).
        if (entry.getPrivileges().contains(Privilege.ContactlessActivation)) {
            RegistryPolicy.stripFromOthers(this, entry, Privilege.ContactlessActivation);
        }
        registry.put(aid, entry);
        bumpUpdateCounter();
    }

    // Called before the entry is removed. Restores spec-defaulted privileges to their fallback (the ISD).
    public void remove(AID aid) {
        var deleted = registry.get(aid);
        if (deleted == null) {
            throw new IllegalStateException("Not present in registry: " + aid);
        }
        if (deleted.getKind() == Kind.ISD) {
            throw new IllegalStateException("ISD cannot be deleted");
        }
        // GPC v2.3.1 6.6.2: Card Reset returns to the ISD.
        if (deleted.getPrivileges().contains(Privilege.CardReset)) {
            RegistryPolicy.grant(isd, Privilege.CardReset);
        }
        // GPC v2.3.1 6.6.2: Final Application returns to the ISD.
        if (deleted.getPrivileges().contains(Privilege.FinalApplication)) {
            RegistryPolicy.grant(isd, Privilege.FinalApplication);
        }
        // GPC v2.3.1 Amd C 7.1: Contactless Activation has no default holder; falls back to 6982.
        registry.remove(aid);
        // GPC v2.3.1 Amd C 3.11.2.3: a DELETE increments the global update counter.
        bumpUpdateCounter();
    }

    public Collection<EngineRegistryEntry> getApplets() {
        // Selectable applets only (APP/SSD/ISD);
        return registry.values().stream().filter(e -> e.getKind() != Kind.PKG).toList();
    }

    public Collection<EngineRegistryEntry> getPackages() {
        return registry.values().stream().filter(e -> e.getKind() == Kind.PKG).toList();
    }

    public Class<? extends Applet> locateApplet(AID packageAid, AID appletAid) {
        var entry = registry.get(packageAid);
        if (entry != null && entry.getKind() == Kind.PKG) {
            var c = entry.getModules().get(appletAid);
            if (c != null) {
                log.debug("Found applet {} in pkg {}", appletAid, entry.getJavaPackageName());
                return c;
            }
        }
        log.warn("pkg {} / applet {} not found in registry.", packageAid, appletAid);
        return null;
    }

    public EngineRegistryEntry getRegistryEntry(AID aid) {
        var sim = Simulator.current();
        var caller = sim.caller();

        // System context bypasses the gate.
        if (caller == null) {
            return selectable(lookup(aid));
        }

        // null target resolves to the caller's own entry.
        if (aid == null || caller.getAID().equals(aid)) {
            return caller;
        }

        // Cross-applet lookup requires GlobalRegistry privilege.
        if (!caller.isPrivileged(GPRegistryEntry.PRIVILEGE_GLOBAL_REGISTRY)) {
            log.warn("getRegistryEntry denied, GlobalRegistry privilege required: caller {} target {}", caller.getAID(), aid);
            return null;
        }

        return selectable(lookup(aid));
    }

    // The org.globalplatform registry API exposes selectable entries only - never ELFs (Kind.PKG).
    private static EngineRegistryEntry selectable(EngineRegistryEntry e) {
        return e != null && e.getKind() != Kind.PKG ? e : null;
    }

    public EngineSecureChannel getSecureChannel() {
        return sc;
    }

    // 2-byte big-endian Global Update Counter
    public byte[] getUpdateCounterBytes() {
        return new byte[]{(byte) ((updateCounter >>> 8) & 0xFF), (byte) (updateCounter & 0xFF)};
    }

    // Bump (wraps at 0xFFFF)
    void bumpUpdateCounter() {
        updateCounter = (updateCounter + 1) & 0xFFFF;
    }

    public void reset() {
        sc.resetSecurity();
        gpin.onCardReset();
        // note: CardReset applet is selected in engine side
    }

    public CVM getGlobalPIN() {
        return gpin;
    }

    public byte getCardState() {
        return isd.getState();
    }

    public boolean lockCard() {
        return setCardLifecycleState(GPSystem.CARD_LOCKED);
    }

    public boolean terminateCard() {
        return setCardLifecycleState(GPSystem.CARD_TERMINATED);
    }

    public boolean setCardLifecycleState(byte newState) {
        // Always reached from applet context (SET STATUS, GP-API setState on the ISD, GPSystem.lock/terminate).
        var caller = Simulator.current().caller();
        byte current = isd.getState();

        boolean allowed = switch (newState) {
            // Pre-issuance, irreversible (GPC v2.3.1 5.1.1.2/5.1.1.3); needs Authorized Management.
            case GPSystem.CARD_INITIALIZED -> current == GPSystem.CARD_OP_READY && caller.isPrivileged(GPRegistryEntry.PRIVILEGE_AUTHORIZED_MANAGEMENT);
            case GPSystem.CARD_SECURED -> (current == GPSystem.CARD_INITIALIZED && caller.isPrivileged(GPRegistryEntry.PRIVILEGE_AUTHORIZED_MANAGEMENT))
                    // Unlock target from CARD_LOCKED (GPC v2.3.1 5.1.1.4, reversible).
                    || (current == GPSystem.CARD_LOCKED && caller.isPrivileged(GPRegistryEntry.PRIVILEGE_CARD_LOCK));
            // Post-issuance, reversible (GPC v2.3.1 5.1.1.4).
            case GPSystem.CARD_LOCKED -> current == GPSystem.CARD_SECURED && caller.isPrivileged(GPRegistryEntry.PRIVILEGE_CARD_LOCK);
            // Terminal state (GPC v2.3.1 5.1.1.5), irreversible from any other state.
            case GPSystem.CARD_TERMINATED -> current != GPSystem.CARD_TERMINATED && caller.isPrivileged(GPRegistryEntry.PRIVILEGE_CARD_TERMINATE);
            default -> false;   // OP_READY isn't a target - there's no transition into it.
        };
        if (!allowed) {
            return false;
        }
        isd.internalForceState(newState);
        bumpUpdateCounter();
        return true;
    }

    // GPSystem.setCardContentState() - self-only shortcut to update own LCS.
    public boolean setCardContentState(byte newState) {
        var caller = Simulator.current().caller();
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
        byte before = caller.getState();
        if (!caller.setState(newState)) {
            return false;
        }
        // GPC v2.3.1 Amd C 3.11.2.3: bump only when the lifecycle actually moved - setState succeeds on a
        // same-state no-op, which is not a content change.
        if (caller.getState() != before) {
            bumpUpdateCounter();
        }
        return true;
    }

    // INSTALL [for extradition] (GPC v2.3.1 11.5.2.3.4): rebind target's associated SD.
    public void extradite(EngineRegistryEntry target, EngineRegistryEntry newSD) {
        target.setParentSD(newSD);
        bumpUpdateCounter();
    }
}
