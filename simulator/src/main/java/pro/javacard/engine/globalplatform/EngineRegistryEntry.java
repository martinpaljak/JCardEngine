// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.*;
import org.globalplatform.GPRegistryEntry;
import org.globalplatform.GPSystem;
import org.globalplatform.contactless.CLAppletEvent;
import org.globalplatform.contactless.GPCLRegistryEntry;
import pro.javacard.engine.core.ReflectiveClassProxy;
import pro.javacard.engine.globalplatform.GPNamedElement.GPInfo;
import pro.javacard.engine.globalplatform.GPNamedElement.GPTag;
import pro.javacard.gp.data.BitField;

import java.util.*;

import static pro.javacard.gp.GPRegistryEntry.*;

// GP(CL)RegistryEntry implementation
public final class EngineRegistryEntry implements GPCLRegistryEntry {

    // Load-file (ELF) initial lifecycle, GPC v2.3.1 11.1.1: LOADED. GPSystem defines no load-file
    // state constant (only APPLICATION_*/CARD_*/SECURITY_DOMAIN_*), so this one stays local. The
    // applet/ISD initial states use GPSystem.APPLICATION_SELECTABLE / CARD_OP_READY directly.
    public static final byte PKG_LOADED = (byte) 0x01;

    private static final short SW_FUNC_NOT_SUPPORTED = 0x6A81;

    private AID aid;                        // mutable: STORE DATA tag 4F renames the ISD (GPC v2.3.1 11.11.2.3)
    private final Object instance;          // null for PKG
    private final boolean exposed;          // ignored for PKG
    private EnumSet<Privilege> privileges;
    private final Kind kind;
    private final AID packageAID;           // load file AID (nullable for APP/SSD/ISD)
    private EngineRegistryEntry parentSD;   // associated SD (mutable: INSTALL [for extradition], 11.5.2.3.4)
    private byte lifecycle;                 // mutable: getState/setState
    private final String javaPackageName;   // PKG only
    private final Map<AID, Class<? extends Applet>> modules; // PKG only

    // ---- CL state (applet-kind only; PKG entries throw on CL methods).
    private byte state = STATE_CL_DEACTIVATED;
    private final LinkedHashSet<AID> crels = new LinkedHashSet<>();
    private final HashMap<GPInfo, byte[]> infos = new HashMap<>();

    // Global Service registration (GPC v2.3.1 8.1.1).
    private final LinkedHashSet<Short> installedServices = new LinkedHashSet<>();
    private final LinkedHashSet<Short> registeredServices = new LinkedHashSet<>();

    // Opaque INSTALL EF System Specific Parameters
    private final LinkedHashMap<GPTag, byte[]> systemParams = new LinkedHashMap<>();

    // STORE DATA / GET DATA data objects (GPC v2.3.1 11.11), keyed by tag.
    private final LinkedHashMap<GPTag, byte[]> data = new LinkedHashMap<>();

    // DELETE tombstone, set by markDisabled().
    private boolean disabled;

    private EngineRegistryEntry(AID aid, Object instance, boolean exposed, EnumSet<Privilege> privileges, Kind kind, AID packageAID, byte initialLifecycle, EngineRegistryEntry parentSD) {
        this.aid = aid;
        this.instance = instance;
        this.exposed = exposed;
        this.privileges = privileges;
        this.kind = kind;
        this.packageAID = packageAID;
        this.lifecycle = initialLifecycle;
        this.parentSD = parentSD == null ? this : parentSD;
        this.javaPackageName = null;
        this.modules = null;
    }

    private EngineRegistryEntry(AID packageAID, String javaPackageName, byte initialLifecycle, EngineRegistryEntry associatedSD) {
        this.aid = packageAID;
        this.instance = null;
        this.exposed = false;
        this.privileges = EnumSet.noneOf(Privilege.class);
        this.kind = Kind.PKG;
        this.packageAID = packageAID;
        this.lifecycle = initialLifecycle;
        this.parentSD = associatedSD;
        this.javaPackageName = javaPackageName;
        this.modules = new TreeMap<>(AIDUtil.comparator());
    }

    // APP/SSD factory. Kind auto-promotes to SSD when the SecurityDomain privilege is present (ISD goes via forISD).
    public static EngineRegistryEntry forApplet(AID aid, Object instance, boolean exposed, EnumSet<Privilege> privileges, AID packageAID, EngineRegistryEntry parentSD) {
        var privSet = copyPrivileges(privileges);
        Kind kind = privSet.contains(Privilege.SecurityDomain) ? Kind.SSD : Kind.APP;
        return new EngineRegistryEntry(aid, instance, exposed, privSet, kind, packageAID, GPSystem.APPLICATION_SELECTABLE, parentSD);
    }

    // APP/SSD factory: byte[] convenience for the GP install boundary.
    public static EngineRegistryEntry forApplet(AID aid, Object instance, boolean exposed, byte[] privBytes, AID packageAID, EngineRegistryEntry parentSD) {
        return forApplet(aid, instance, exposed, decodePrivileges(privBytes), packageAID, parentSD);
    }

    // ISD factory used by bootstrap. The ISD self-parents (GPC v2.3.1 7.2) and is not extraditable.
    static EngineRegistryEntry forISD(AID aid, Object instance, AID packageAID) {
        return new EngineRegistryEntry(aid, instance, true, copyPrivileges(SecurityDomainApplet.ISD_DEFAULT_PRIVILEGES), Kind.ISD, packageAID, GPSystem.CARD_OP_READY, null);
    }

    // PKG factory. associatedSD is the SD that issued the load (real GP: INSTALL [for load]).
    static EngineRegistryEntry forPackage(AID packageAID, String javaPackageName, EngineRegistryEntry associatedSD) {
        return new EngineRegistryEntry(packageAID, javaPackageName, PKG_LOADED, associatedSD);
    }

    static EnumSet<Privilege> decodePrivileges(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return EnumSet.noneOf(Privilege.class);
        }
        if (bytes.length != 1 && bytes.length != 3) {
            throw new IllegalArgumentException("Privilege field must be 0, 1 or 3 bytes, got " + bytes.length);
        }
        var parsed = BitField.parse(Privilege.class, bytes, 1, 3);
        return parsed.isEmpty() ? EnumSet.noneOf(Privilege.class) : EnumSet.copyOf(parsed);
    }

    private static EnumSet<Privilege> copyPrivileges(EnumSet<Privilege> privileges) {
        return privileges.isEmpty() ? EnumSet.noneOf(Privilege.class) : EnumSet.copyOf(privileges);
    }

    public Applet getApplet() {
        if (instance == null) {
            return null;
        }
        if (exposed) {
            return (Applet) instance;
        }
        try {
            return ReflectiveClassProxy.proxy(instance, Applet.class);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    String getJavaPackageName() {
        return javaPackageName;
    }

    Map<AID, Class<? extends Applet>> getModules() {
        return modules == null ? Map.of() : Collections.unmodifiableMap(modules);
    }

    // GET DATA / STORE DATA data objects keyed by tag (clone on the boundary, never share the array).
    byte[] getData(GPTag element) {
        byte[] v = data.get(element);
        return v == null ? null : v.clone();
    }

    void putData(GPTag element, byte[] value) {
        if (value == null) {
            data.remove(element);
            return;
        }
        data.put(element, value.clone());
    }

    public Kind getKind() {
        return kind;
    }

    AID getPackageAID() {
        return packageAID;
    }

    EngineRegistryEntry getParentSD() {
        return parentSD;
    }

    // INSTALL [for extradition] (GPC v2.3.1 11.5.2.3.4): rebind to a new associated SD. OPEN-only; ISD never extradited.
    void setParentSD(EngineRegistryEntry newParent) {
        if (newParent == null) {
            throw new IllegalArgumentException("parent SD must not be null");
        }
        this.parentSD = newParent;
    }

    void addModule(AID appletAid, Class<? extends Applet> appletClass) {
        if (kind != Kind.PKG) {
            throw new IllegalStateException("Modules only allowed on PKG entries");
        }
        modules.put(appletAid, appletClass);
    }

    @Override
    public String toString() {
        if (disabled) {
            return "<deleted %s>".formatted(aid);
        }
        String lc = switch (kind) {
            case ISD -> ByteEnum.fromByte(ISDLifeCycle.class, lifecycle).name();
            case APP -> ByteEnum.fromByte(APPLifeCycle.class, lifecycle).name();
            case PKG -> ByteEnum.fromByte(PKGLifeCycle.class, lifecycle).name();
            case SSD -> ByteEnum.fromByte(SSDLifeCycle.class, lifecycle).name();
        };
        // Compact log identity: KIND(aid-hex lifecycle [privileges]); privileges omitted when none.
        return "%s(%s %s%s)".formatted(kind, aid, lc, privileges.isEmpty() ? "" : " " + privileges);
    }

    void markDisabled() {
        this.disabled = true;
    }

    public boolean isDisabled() {
        return disabled;
    }

    private void checkAlive() {
        if (disabled) {
            SystemException.throwIt(SystemException.ILLEGAL_USE);
        }
    }

    @Override
    public AID getAID() {
        // Exempt from checkAlive(): getAID() stays usable on a disabled entry to identify the dead AID.
        return aid;
    }

    // The registry key must be re-pointed in lockstep; only GlobalPlatformEngine.renameISD calls this.
    void setAID(AID aid) {
        this.aid = aid;
    }

    @Override
    public byte getState() {
        checkAlive();
        return lifecycle;
    }

    // GPC v2.3.1 Amd C 11.4.3.1 / Table 8-1: 9F70 value is [Life Cycle State, Contactless Activation
    // State]. PKG entries never leave CL DEACTIVATED, so the second byte is 00 as required for ELF.
    byte[] lifecycleState() {
        return new byte[]{lifecycle, state};
    }

    // Bare mutator bypassing GP-API validation; for engine plumbing (setCardLifecycleState, boot).
    void internalForceState(byte newState) {
        this.lifecycle = newState;
    }

    @Override
    public boolean setState(byte newState) {
        checkAlive();
        var sim = Simulator.current();
        var caller = sim.caller();
        if (caller == null) {
            return false;
        }
        if (this.kind == Kind.ISD) {
            return sim.gp().setCardLifecycleState(newState);
        }
        // GPC v2.3.1 5.3.1.3: lock requires self or Global Lock; only a Global Lock holder may unlock.
        boolean lockAllowed = caller.getAID().equals(this.aid) || caller.isPrivileged(GPRegistryEntry.PRIVILEGE_GLOBAL_LOCK);
        boolean unlockAllowed = caller.isPrivileged(GPRegistryEntry.PRIVILEGE_GLOBAL_LOCK);
        return transition(newState, lockAllowed, unlockAllowed);
    }

    // Guarded lifecycle transition shared by the JC-API path (setState) and the SET STATUS
    // [for application] admin path. lockAllowed/unlockAllowed gate the b8 LOCK bit per the
    // caller's authorization, already decided upstream; this method only enforces the
    // GPC v2.3.1 5.3.1 transition legality (lock-bit mechanics + INSTALLED/SELECTABLE
    // irreversibility) and mutates the lifecycle on success.
    boolean transition(byte newState, boolean lockAllowed, boolean unlockAllowed) {
        int current = this.lifecycle & 0xFF;
        int next = newState & 0xFF;
        if (current == next) {
            return true;
        }
        boolean newLocked = (newState & (byte) 0x80) != 0;
        boolean curLocked = (this.lifecycle & (byte) 0x80) != 0;
        if (newLocked && !curLocked) {
            // High bit = lock; b7..b1 ignored.
            if (!lockAllowed) {
                return false;
            }
            this.lifecycle = (byte) (this.lifecycle | 0x80);
            return true;
        }
        if (!newLocked && curLocked) {
            if (!unlockAllowed) {
                return false;
            }
            this.lifecycle = (byte) (this.lifecycle & 0x7F);
            return true;
        }
        if (curLocked) {
            // b7..b1 ignored on a locked entry: no-op success.
            return true;
        }
        // GPRegistryEntry.setState: INSTALLED -> SELECTABLE is rejected (use INSTALL [for make selectable]).
        if (current == 0x03 && next == 0x07) {
            return false;
        }
        // GPC v2.3.1 5.3.1.2: INSTALLED -> SELECTABLE irreversible; reject regression to 0x03/0x07.
        if (next == 0x03 && current > 0x03) {
            return false;
        }
        if (next == 0x07 && current > 0x07) {
            return false;
        }
        // GPC v2.3.1 5.3.2.3: SSD SELECTABLE -> PERSONALIZED (0x0F) irreversible; no regression below 0x0F.
        if (this.kind == Kind.SSD && current >= 0x0F && next < 0x0F) {
            return false;
        }
        this.lifecycle = newState;
        return true;
    }

    @Override
    public short getPrivileges(byte[] buf, short off) throws ArrayIndexOutOfBoundsException {
        checkAlive();
        byte[] bytes = BitField.encode(privileges, 3);
        Util.arrayCopyNonAtomic(bytes, (short) 0, buf, off, (short) bytes.length);
        return (short) (off + bytes.length);
    }

    @Override
    public boolean isPrivileged(byte b) {
        checkAlive();
        Privilege p = GPPrivilege.toPrivilege(b);
        return p != null && privileges.contains(p);
    }

    EnumSet<Privilege> getPrivileges() {
        return copyPrivileges(privileges);
    }

    void setPrivileges(EnumSet<Privilege> p) {
        privileges = copyPrivileges(p);
    }

    @Override
    public boolean isAssociated(AID sdAID) {
        checkAlive();
        return parentSD.getAID().equals(sdAID);
    }

    // GPC v2.3.1 8.1.1 unique service registration.
    @Override
    public void registerService(short sServiceName) throws ISOException {
        checkAlive();
        if (!privileges.contains(Privilege.GlobalService)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (!installedServices.isEmpty() && !matchesRecorded(sServiceName)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        for (var e : Simulator.current().gp().getApplets()) {
            if (e != this && e.registeredServices.contains(sServiceName)) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        }
        registeredServices.add(sServiceName);
    }

    // GPC v2.3.1 8.1.1 deregistration
    @Override
    public void deregisterService(short sServiceName) throws ISOException {
        checkAlive();
        if (!privileges.contains(Privilege.GlobalService)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (!registeredServices.remove(sServiceName)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    // GPC v2.3.1 8.1.1: requested name matches a recorded one exactly, or a recorded family-only
    // (id byte 00) name covers any requested name with the same family byte.
    private boolean matchesRecorded(short requested) {
        if (installedServices.contains(requested)) {
            return true;
        }
        short family = (short) (requested & 0xFF00);
        return installedServices.contains(family);
    }

    // Install-path recorder for CB Global Service Parameters (GPC v2.3.1 8.1.1): NOT uniqueness-checked.
    void recordInstalledService(short serviceName) {
        installedServices.add(serviceName);
    }

    @Override
    public byte getCLState() {
        checkAlive();
        requireAppletKind();
        return state;
    }

    @Override
    public byte setCLState(byte newState) {
        checkAlive();
        requireAppletKind();
        return ContactlessEngine.setCLState(this, newState);
    }

    @Override
    public GPCLRegistryEntry getNextCRELApplication(GPCLRegistryEntry entry) {
        checkAlive();
        SystemException.throwIt(SystemException.ILLEGAL_USE);
        return null;
    }

    @Override
    public void addToCRELApplicationList(byte[] buf, short offset, short length) {
        checkAlive();
        requireAppletKind();
        var crelAid = new AID(buf, offset, (byte) length);
        if (crels.add(crelAid)) {
            // GPC v2.3.1 Amd C 3.11.2.3: a CREL-list change is a counted registry event, like setInfo/setCLState.
            Simulator.current().gp().bumpUpdateCounter();
            // GPC v2.3.1 Amd C 3.8.2: notify after mutation so the callee sees itself in the set.
            ContactlessEngine.notifyCRELListChange(this, crelAid, CLAppletEvent.EVENT_CREL_ADDED);
        }
    }

    @Override
    public void removeFromCRELApplicationList(byte[] buf, short offset, short length) {
        checkAlive();
        requireAppletKind();
        var crelAid = new AID(buf, offset, (byte) length);
        if (crels.remove(crelAid)) {
            Simulator.current().gp().bumpUpdateCounter();
            ContactlessEngine.notifyCRELListChange(this, crelAid, CLAppletEvent.EVENT_CREL_REMOVED);
        }
    }

    // getInfo/setInfo (GPC v2.3.1 Amd C 11.2.3)
    @Override
    public short getInfo(byte[] buffer, short offset, short info) {
        checkAlive();
        requireAppletKind();
        var element = GPData.byInfo(info).orElse(null);
        if (element == null) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        var value = infos.get(element);
        if (value == null) {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }
        System.arraycopy(value, 0, buffer, offset, value.length);
        return (short) (offset + value.length);
    }

    @Override
    public short setInfo(byte[] buffer, short offset, short length, short info) {
        checkAlive();
        requireAppletKind();
        var element = GPData.byInfo(info).orElse(null);
        if (element == null) {
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED);
        }
        return setInfoInternal(buffer, offset, length, element);
    }

    @Override
    public GPCLRegistryEntry getNextConflictingApplication(GPCLRegistryEntry entry) {
        checkAlive();
        SystemException.throwIt(SystemException.ILLEGAL_USE);
        return null;
    }

    @Override
    public void joinGroup(AID head) {
        checkAlive();
        SystemException.throwIt(SystemException.ILLEGAL_USE);
    }

    @Override
    public GPCLRegistryEntry getNextGroupMember(GPCLRegistryEntry entry) {
        checkAlive();
        SystemException.throwIt(SystemException.ILLEGAL_USE);
        return null;
    }

    @Override
    public void addToGroupAuthorizationList(byte[] buf, short offset, short length) {
        checkAlive();
        SystemException.throwIt(SystemException.ILLEGAL_USE);
    }

    @Override
    public void removeFromGroupAuthorizationList(byte[] buf, short offset, short length) {
        checkAlive();
        SystemException.throwIt(SystemException.ILLEGAL_USE);
    }

    @Override
    public void setPartialSelectionOrder(boolean topBottom) {
        checkAlive();
        SystemException.throwIt(SystemException.ILLEGAL_USE);
    }

    // GPC v2.3.1 Amd C: iterate applications holding THIS AID in their CREL list. Stateless cursor (oEntry)
    @Override
    public GPCLRegistryEntry getNextReferencingApplication(GPCLRegistryEntry oEntry) {
        checkAlive();
        requireAppletKind();
        var sim = Simulator.current();
        var caller = sim.caller();
        boolean callerIsSelf = caller.getAID().equals(getAID());
        boolean callerPrivileged = caller.isPrivileged(GPCLRegistryEntry.PRIVILEGE_CONTACTLESS_ACTIVATION);
        if (!callerIsSelf && !callerPrivileged) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Validate oEntry: SecurityException for non-engine instances, ILLEGAL_USE for a tombstoned one.
        EngineRegistryEntry cursor = null;
        if (oEntry != null) {
            if (!(oEntry instanceof EngineRegistryEntry o)) {
                throw new SecurityException();
            }
            if (o.disabled) {
                SystemException.throwIt(SystemException.ILLEGAL_USE);
            }
            cursor = o;
        }

        // X references this iff X.crels contains this.AID. Registry order is the AID comparator, stable.
        var thisAID = getAID();
        var refs = new ArrayList<EngineRegistryEntry>();
        for (var e : sim.gp().getApplets()) {
            if (e.kind != Kind.PKG && e.crels.contains(thisAID)) {
                refs.add(e);
            }
        }

        if (refs.isEmpty()) {
            return null;
        }
        if (cursor == null) {
            return refs.get(0);
        }
        // Identity equals; cursor is the verified live instance.
        int idx = refs.indexOf(cursor);
        if (idx < 0 || idx + 1 >= refs.size()) {
            return null;
        }
        return refs.get(idx + 1);
    }

    @Override
    public boolean isGroupHead() {
        checkAlive();
        SystemException.throwIt(SystemException.ILLEGAL_USE);
        return false;
    }

    @Override
    public boolean isGroupMember() {
        checkAlive();
        SystemException.throwIt(SystemException.ILLEGAL_USE);
        return false;
    }

    // Unmodifiable insertion-ordered (LinkedHashSet) view of the CREL AIDs - deterministic fan-out.
    Set<AID> internalGetCRELs() {
        return Collections.unmodifiableSet(crels);
    }

    byte internalGetCLState() {
        return state;
    }

    // Apply the activation state byte, return whether it changed. No validation; caller fires the event.
    boolean internalApplyCLState(byte newState) {
        boolean changed = newState != this.state;
        this.state = newState;
        return changed;
    }

    // Install-path bypass of the caller-identity gate: SD writes Application Information from the
    // INSTALL TLV. Length 0 clears the slot (GPC v2.3.1 Amd C 11.2.3).
    short setInfoInternal(byte[] buffer, short offset, short length, GPInfo element) {
        boolean changed;
        if (length == 0) {
            changed = infos.remove(element) != null;
        } else {
            var copy = new byte[length];
            System.arraycopy(buffer, offset, copy, 0, length);
            changed = !Arrays.equals(infos.put(element, copy), copy);
        }
        // GPC v2.3.1 Amd C 3.10.2 / 3.10.3 + 3.11.2.3: a User Interaction parameter change notifies the
        // CREL / CRS Applications and advances the update counter, exactly like a CL activation change.
        if (changed) {
            Simulator.current().gp().bumpUpdateCounter();
            ContactlessEngine.notifyContactlessEvent(this, element.event());
        }
        return (short) (offset + length);
    }

    // Opaque INSTALL EF System Specific Parameter store (GPC v2.3.1 Table 11-49). Raw value bytes,
    // keyed by the GPData GPTag; no enforcement.
    void putSystemParam(GPTag element, byte[] value) {
        systemParams.put(element, value.clone());
    }

    private void requireAppletKind() {
        if (kind == Kind.PKG) {
            // PKG implements GPCLRegistryEntry only for the cast rule; no CL lifecycle.
            SystemException.throwIt(SystemException.ILLEGAL_USE);
        }
    }

    // JC GP API privilege byte (PRIVILEGE_*, an identifier 0x00..0x13) <-> GPPro Privilege.
    // Distinct from the BitField bit-mask encoding used on the wire.
    private enum GPPrivilege {
        SECURITY_DOMAIN(GPRegistryEntry.PRIVILEGE_SECURITY_DOMAIN, Privilege.SecurityDomain),
        DAP_VERIFICATION(GPRegistryEntry.PRIVILEGE_DAP_VERIFICATION, Privilege.DAPVerification),
        DELEGATED_MANAGEMENT(GPRegistryEntry.PRIVILEGE_DELEGATED_MANAGEMENT, Privilege.DelegatedManagement),
        CARD_LOCK(GPRegistryEntry.PRIVILEGE_CARD_LOCK, Privilege.CardLock),
        CARD_TERMINATE(GPRegistryEntry.PRIVILEGE_CARD_TERMINATE, Privilege.CardTerminate),
        CARD_RESET(GPRegistryEntry.PRIVILEGE_CARD_RESET, Privilege.CardReset),
        CVM_MANAGEMENT(GPRegistryEntry.PRIVILEGE_CVM_MANAGEMENT, Privilege.CVMManagement),
        MANDATED_DAP(GPRegistryEntry.PRIVILEGE_MANDATED_DAP, Privilege.MandatedDAPVerification),
        TRUSTED_PATH(GPRegistryEntry.PRIVILEGE_TRUSTED_PATH, Privilege.TrustedPath),
        AUTHORIZED_MANAGEMENT(GPRegistryEntry.PRIVILEGE_AUTHORIZED_MANAGEMENT, Privilege.AuthorizedManagement),
        TOKEN_VERIFICATION(GPRegistryEntry.PRIVILEGE_TOKEN_VERIFICATION, Privilege.TokenVerification),
        GLOBAL_DELETE(GPRegistryEntry.PRIVILEGE_GLOBAL_DELETE, Privilege.GlobalDelete),
        GLOBAL_LOCK(GPRegistryEntry.PRIVILEGE_GLOBAL_LOCK, Privilege.GlobalLock),
        GLOBAL_REGISTRY(GPRegistryEntry.PRIVILEGE_GLOBAL_REGISTRY, Privilege.GlobalRegistry),
        FINAL_APPLICATION(GPRegistryEntry.PRIVILEGE_FINAL_APPLICATION, Privilege.FinalApplication),
        GLOBAL_SERVICE(GPRegistryEntry.PRIVILEGE_GLOBAL_SERVICE, Privilege.GlobalService),
        RECEIPT_GENERATION(GPRegistryEntry.PRIVILEGE_RECEIPT_GENERATION, Privilege.ReceiptGeneration),
        CIPHERED_LOAD_FILE_DATA_BLOCK(GPRegistryEntry.PRIVILEGE_CIPHERED_LOAD_FILE_DATA_BLOCK, Privilege.CipheredLoadFileDataBlock),
        CONTACTLESS_ACTIVATION(GPCLRegistryEntry.PRIVILEGE_CONTACTLESS_ACTIVATION, Privilege.ContactlessActivation),
        CONTACTLESS_SELF_ACTIVATION(GPCLRegistryEntry.PRIVILEGE_CONTACTLESS_SELF_ACTIVATION, Privilege.ContactlessSelfActivation);

        final byte api;
        final Privilege gp;

        GPPrivilege(byte api, Privilege gp) {
            this.api = api;
            this.gp = gp;
        }

        private static final Map<Byte, Privilege> TO_PRIV = new HashMap<>();
        private static final Map<Privilege, Byte> TO_BYTE = new EnumMap<>(Privilege.class);

        static {
            for (var v : values()) {
                TO_PRIV.put(v.api, v.gp);
                TO_BYTE.put(v.gp, v.api);
            }
        }

        // null if the byte/privilege has no API counterpart.
        static Privilege toPrivilege(byte b) {
            return TO_PRIV.get(b);
        }

        static Byte toByte(Privilege p) {
            return TO_BYTE.get(p);
        }
    }
}
