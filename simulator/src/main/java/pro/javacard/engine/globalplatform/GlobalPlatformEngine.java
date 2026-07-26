// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.SystemException;
import org.globalplatform.CVM;
import org.globalplatform.GPRegistryEntry;
import org.globalplatform.GPSystem;
import org.globalplatform.contactless.GPCLRegistryEntry;
import org.globalplatform.contactless.GPCLSystem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.engine.JavaCardEngineException;
import pro.javacard.gp.GPRegistryEntry.Kind;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.data.BitField;

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

    // GPC v2.3.1 Amd C 8.3 / 4.2: the OPEN-owned default Initial Contactless Activation State, applied to an
    // Application installed without its own tag 81. ISD-settable via empty-AID INSTALL [for registry update].
    CLState defaultInitial = CLState.DEACTIVATED;

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
        isd.setContext(lookup(SecurityDomainApplet.SSD_PACKAGE_AID).getContext());
    }

    // Virtual load: collapses INSTALL [for load] + LOAD blocks into one call; null parent = ISD.
    public void loadClass(AID packageAid, AID appletAid, Class<? extends Applet> appletClass, EngineRegistryEntry parent) {
        var pkg = lookup(packageAid);
        if (pkg == null) {
            pkg = EngineRegistryEntry.forPackage(packageAid, appletClass.getPackageName(), parent != null ? parent : isd);
            registry.put(packageAid, pkg);
        } else if (pkg.getKind() != Kind.PKG) {
            throw new JavaCardEngineException("AID already in use by a non-PKG entry: " + packageAid);
        }

        if (pkg.getModules().containsKey(appletAid)) {
            log.error("Applet already present");
            throw new JavaCardEngineException("Applet already loaded");
        }

        pkg.addModule(appletAid, appletClass);
        log.info("Loaded applet {}", appletClass.getCanonicalName());
    }

    // Host install has no prior LOAD: creates the PKG entry and module mapping for the
    // synthesized load file if absent; safe to call again after delete or for same-package siblings.
    public EngineRegistryEntry ensurePackage(AID packageAid, AID appletAid, Class<? extends Applet> appletClass) {
        var pkg = lookup(packageAid);
        if (pkg == null || !pkg.getModules().containsKey(appletAid)) {
            loadClass(packageAid, appletAid, appletClass, null);
            pkg = lookup(packageAid);
        }
        return pkg;
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

    // Register the default CRS applet. Deferred out of the constructor because install() runs applet
    // code that uses JCSystem and so needs the Simulator to be current; build() calls this inside
    // asCurrent(). Installed exposed: it is an engine class, not applet code to isolate.
    public void bootstrap() {
        addBuiltinPackage(EngineCRSApplet.CRS_PACKAGE_AID, EngineCRSApplet.CRS_AID, EngineCRSApplet.class);
        var privileges = BitField.encode(EnumSet.of(Privilege.ContactlessActivation, Privilege.GlobalRegistry), 3);
        var crsEntry = Simulator.current().internalInstallApplet(EngineCRSApplet.CRS_AID, EngineCRSApplet.class, privileges, null, true,
                lookup(EngineCRSApplet.CRS_PACKAGE_AID));
        // GPC v2.3.1 Amd C 8.1: the CRS is contactless-ACTIVATED from boot, else it is unreachable over the
        // contactless interface it exists to manage.
        crsEntry.initial = CLState.ACTIVATED;
        crsEntry.state = GPCLRegistryEntry.STATE_CL_ACTIVATED;
        // GPC v2.3.1 Amd C 3.11.2.3: the counter is zero on the issued card, which already carries the CRS.
        updateCounter = 0;
    }

    public EngineRegistryEntry isd() {
        return isd;
    }

    // Resolve any entry by AID (ELFs included); callers needing selectable applets filter Kind.PKG.
    public EngineRegistryEntry lookup(AID lookupAid) {
        log.trace("Searching registry for {}", lookupAid);
        var entry = registry.get(lookupAid);
        if (entry == null) {
            log.trace("Application not found: {}", lookupAid);
        }
        return entry;
    }

    // Mint the entry install() will run for. GPC v2.3.1 9.3.6: the applet inherits its load file's parent
    // SD and firewall context (JCRE 6.1.2). It stays out of the registry until publish, so nothing can
    // look it up and it leaves no trace if install() throws.
    public EngineRegistryEntry newApplet(AID aid, boolean exposed, byte[] privileges, EngineRegistryEntry pkg) {
        Objects.requireNonNull(pkg, "an applet requires a package");
        var entry = EngineRegistryEntry.forApplet(aid, exposed, privileges, pkg.getAID(), pkg.getParentSD());
        entry.setContext(pkg.getContext());
        return entry;
    }

    // The register() commit point: the instance is attached and the entry becomes findable. Taking the
    // single-holder privileges happens here rather than at newApplet, so an install() that throws does
    // not leave another Application stripped for an installation that never happened.
    public void publish(EngineRegistryEntry entry, Object instance) {
        entry.setInstance(instance);
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
        registry.put(entry.getAID(), entry);
        bumpUpdateCounter();
    }

    // Called before the entry is removed. Restores spec-defaulted privileges to their fallback (the ISD).
    public void remove(EngineRegistryEntry deleted) {
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
        registry.remove(deleted.getAID());
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
        // The JCRE context bypasses the gate. Asked of the context, because an applet that has not
        // registered runs in its own context and must not inherit the system's rights.
        if (Context.JCRE.equals(Simulator.current().activeContext())) {
            return selectable(lookup(aid));
        }

        // GP API 1.8 GPSystem.getRegistryEntry: an entry is returned only "if it was found in the
        // GlobalPlatform Registry". Before register() the caller has neither an entry of its own nor an
        // identity to gate a cross-application lookup with.
        var caller = Simulator.current().currentApplication();
        if (caller == null) {
            return null;
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

    // GPCLSystem.getNextGPCLRegistryEntry (GPC v2.3.1 Amd C): stateless cursor over CL-activated applets
    // of the requested Application Family, in registry (AID) order. The caller's visible set follows the
    // spec roles: GLOBAL REGISTRY or CONTACTLESS ACTIVATION sees all; a Security Domain sees its directly
    // or indirectly associated applications; a CREL Application sees the applications referencing it. A
    // caller holding none of these roles gets SW_CONDITIONS_NOT_SATISFIED.
    public GPCLRegistryEntry nextContactlessEntry(GPCLRegistryEntry oEntry, short family) {
        var caller = Simulator.current().currentApplication();
        if (caller == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        EngineRegistryEntry cursor = null;
        if (oEntry != null) {
            if (!(oEntry instanceof EngineRegistryEntry o)) {
                throw new SecurityException();
            }
            if (o.isDisabled()) {
                SystemException.throwIt(SystemException.ILLEGAL_USE);
            }
            cursor = o;
        }
        boolean seesAll = caller.isPrivileged(GPRegistryEntry.PRIVILEGE_GLOBAL_REGISTRY)
                || caller.isPrivileged(GPCLRegistryEntry.PRIVILEGE_CONTACTLESS_ACTIVATION);
        boolean isSD = caller.isPrivileged(GPRegistryEntry.PRIVILEGE_SECURITY_DOMAIN);
        AID callerAID = caller.getAID();
        boolean referencedAsCREL = false;
        var visible = new ArrayList<EngineRegistryEntry>();
        for (var e : getApplets()) {
            // A CREL relation counts even for a deactivated app: it authorizes the caller, just yields nothing here.
            boolean crel = e.internalGetCRELs().contains(callerAID);
            referencedAsCREL |= crel;
            if (e.internalGetCLState() != GPCLRegistryEntry.STATE_CL_ACTIVATED || !familyMatches(e, family)) {
                continue;
            }
            if (seesAll || crel || (isSD && associatedTo(e, caller))) {
                visible.add(e);
            }
        }
        if (!seesAll && !isSD && !referencedAsCREL) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (visible.isEmpty()) {
            return null;
        }
        if (cursor == null) {
            return visible.get(0);
        }
        int idx = visible.indexOf(cursor);
        return idx < 0 || idx + 1 >= visible.size() ? null : visible.get(idx + 1);
    }

    // AFI_ANY matches all; otherwise compare the LSB (the AFI byte) against the stored Application Family,
    // tolerating the 1-byte install value vs the 2-byte 00||AFI API form. Absent family never matches.
    private static boolean familyMatches(EngineRegistryEntry e, short family) {
        if (family == GPCLSystem.AFI_ANY) {
            return true;
        }
        byte[] fam = e.infos.get(GPData.APPLICATION_FAMILY);
        return fam != null && fam.length > 0 && (fam[fam.length - 1] & 0xFF) == (family & 0xFF);
    }

    // Directly or indirectly associated: walk the entry's associated-SD chain (ISD is self-parented).
    private static boolean associatedTo(EngineRegistryEntry entry, EngineRegistryEntry sd) {
        AID sdAID = sd.getAID();
        var p = entry.getParentSD();
        while (!p.getAID().equals(sdAID)) {
            var parent = p.getParentSD();
            if (parent == p) {
                return false;
            }
            p = parent;
        }
        return true;
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
        var caller = Simulator.current().currentApplication();
        if (caller == null) {
            return false;
        }
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
        return true;
    }

    // GPSystem.setCardContentState() - self-only shortcut to update own LCS.
    public boolean setCardContentState(byte newState) {
        var caller = Simulator.current().currentApplication();
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
        if (!caller.setState(newState)) {
            return false;
        }
        return true;
    }

    // STORE DATA tag 4F (GPC v2.3.1 11.11.2.3): adopt a new ISD AID by re-keying the registry.
    public void renameISD(AID newAid) {
        if (lookup(newAid) != null) {
            throw new IllegalArgumentException("AID already in use: " + newAid);
        }
        registry.remove(isd.getAID());
        isd.setAID(newAid);
        registry.put(newAid, isd);
    }

    // INSTALL [for extradition] (GPC v2.3.1 11.5.2.3.4): rebind target's associated SD.
    public void extradite(EngineRegistryEntry target, EngineRegistryEntry newSD) {
        target.setParentSD(newSD);
    }
}
