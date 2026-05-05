// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.*;
import org.globalplatform.GPRegistryEntry;
import pro.javacard.engine.core.ReflectiveClassProxy;
import pro.javacard.gp.data.BitField;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Map;
import java.util.TreeMap;

import static pro.javacard.gp.GPRegistryEntry.*;

/**
 * Unified registry entry. Holds both APP/SSD/ISD applet instances and PKG load files.
 * Implements the GP API {@link GPRegistryEntry} so the same instance is returned via
 * {@code GPSystem.getRegistryEntry(...)}.
 */
public final class EngineRegistryEntry implements GPRegistryEntry {

    // Default initial lifecycle for APP/SSD entries — SELECTABLE per GPC v2.3.1 11.1.1 (Table 11-4).
    public static final byte APP_SELECTABLE = (byte) 0x07;
    // Default initial lifecycle for PKG entries — LOADED per GPC v2.3.1 11.1.1 (Table 11-3).
    public static final byte PKG_LOADED = (byte) 0x01;
    // Default initial lifecycle for ISD — OP_READY per GPC v2.3.1 11.1.1 (Table 11-6).
    public static final byte ISD_OP_READY = (byte) 0x01;

    private final AID aid;
    private final Object instance;          // null for PKG
    private final boolean exposed;          // ignored for PKG
    private EnumSet<Privilege> privileges;
    private final Kind kind;
    private final AID packageAID;           // load file AID (nullable for APP/SSD/ISD)
    private AID parentSD;                   // associated SD (mutable: INSTALL [for extradition], 11.5.2.3.4)
    private byte lifecycle;                 // mutable: getState/setState
    private final String javaPackageName;   // only for PKG
    private final Map<AID, Class<? extends Applet>> modules; // only for PKG

    private EngineRegistryEntry(AID aid, Object instance, boolean exposed,
                                EnumSet<Privilege> privileges, Kind kind,
                                AID packageAID, byte initialLifecycle, AID parentSD) {
        this.aid = aid;
        this.instance = instance;
        this.exposed = exposed;
        this.privileges = privileges;
        this.kind = kind;
        this.packageAID = packageAID;
        this.lifecycle = initialLifecycle;
        this.parentSD = parentSD;
        this.javaPackageName = null;
        this.modules = null;
    }

    private EngineRegistryEntry(AID packageAID, String javaPackageName, byte initialLifecycle, AID associatedSD) {
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

    // APP/SSD factory (EnumSet-first). The Kind is auto-promoted to SSD when the SecurityDomain
    // privilege is present, mirroring gp-pro's GPRegistry which derives Kind from the privilege bit.
    // ISD entries go through forISD; the ISD is special and not derivable from privileges alone.
    public static EngineRegistryEntry forApplet(AID aid, Object instance, boolean exposed, EnumSet<Privilege> privileges, AID packageAID, AID parentSD) {
        var privSet = copyPrivileges(privileges);
        Kind kind = privSet.contains(Privilege.SecurityDomain) ? Kind.SSD : Kind.APP;
        return new EngineRegistryEntry(aid, instance, exposed, privSet, kind, packageAID, APP_SELECTABLE, parentSD);
    }

    // APP/SSD factory: byte[] convenience for the GP install boundary. Kind auto-promotion as above.
    public static EngineRegistryEntry forApplet(AID aid, Object instance, boolean exposed, byte[] privBytes, AID packageAID, AID parentSD) {
        return forApplet(aid, instance, exposed, decodePrivileges(privBytes), packageAID, parentSD);
    }

    // ISD factory: explicit override used by the bootstrap site that "plants" the card manager entry.
    // The ISD self-parents because GPC v2.3.1 7.2 states that the Issuer Security Domain is
    // effectively associated with itself, its establishment on the card is not defined by
    // GlobalPlatform, and it is not subject to extradition.
    public static EngineRegistryEntry forISD(AID aid, Object instance, boolean exposed, EnumSet<Privilege> privileges, AID packageAID) {
        return new EngineRegistryEntry(aid, instance, exposed, copyPrivileges(privileges), Kind.ISD, packageAID, ISD_OP_READY, aid);
    }

    // PKG factory. The associated SD is the one that "issued" the load (real GP: INSTALL [for load]).
    // Mirrors the role parentSD plays for APP/SSD entries — see resolveMasterKey()'s walk.
    public static EngineRegistryEntry forPackage(AID packageAID, String javaPackageName, AID associatedSD) {
        return new EngineRegistryEntry(packageAID, javaPackageName, PKG_LOADED, associatedSD);
    }

    public static EnumSet<Privilege> decodePrivileges(byte[] bytes) {
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

    public String getJavaPackageName() {
        return javaPackageName;
    }

    public Map<AID, Class<? extends Applet>> getModules() {
        return modules == null ? Map.of() : Collections.unmodifiableMap(modules);
    }

    public Kind getKind() {
        return kind;
    }

    public AID getPackageAID() {
        return packageAID;
    }

    public AID getParentSD() {
        return parentSD;
    }

    // Mutator for INSTALL [for extradition] (GPC v2.3.1 11.5.2.3.4 / Table 11-45): rebinds this entry
    // to a new associated SD. Should only be called from the extradition path on the
    // OPEN; user code has no API surface to reach this. The ISD cannot be extradited
    // (it is its own associated SD by definition); enforced by callers.
    public void setParentSD(AID newParent) {
        if (newParent == null) {
            throw new IllegalArgumentException("parent SD must not be null");
        }
        this.parentSD = newParent;
    }

    public void addModule(AID appletAid, Class<? extends Applet> appletClass) {
        if (kind != Kind.PKG) {
            throw new IllegalStateException("Modules only allowed on PKG entries");
        }
        modules.put(appletAid, appletClass);
    }

    @Override
    public String toString() {
        String lc = switch (kind) {
            case ISD -> ByteEnum.fromByte(ISDLifeCycle.class, lifecycle).name();
            case APP -> ByteEnum.fromByte(APPLifeCycle.class, lifecycle).name();
            case PKG -> ByteEnum.fromByte(PKGLifeCycle.class, lifecycle).name();
            case SSD -> ByteEnum.fromByte(SSDLifeCycle.class, lifecycle).name();
        };
        return "%s(%s, %s, %s, privs=%s)".formatted(kind, AIDUtil.toString(aid),
                packageAID == null ? "-" : AIDUtil.toString(packageAID), lc, privileges);
    }

    // ---------- org.globalplatform.GPRegistryEntry implementation ----------

    @Override
    public AID getAID() {
        return aid;
    }

    @Override
    public byte getState() {
        return lifecycle;
    }

    // Engine-internal bare mutator that bypasses the GP API validation rules; used by engine
    // plumbing such as GlobalPlatform.setCardLifecycleState (which has its own card-LCS state
    // machine and privilege checks) and the boot-time entry construction path.
    void internalForceState(byte newState) {
        this.lifecycle = newState;
    }

    // GP API GPRegistryEntry.setState (export file v1.8) — implements the GlobalPlatform Card
    // Specification v2.3.1 chapter-5 transition rules. ISD entries route into the card-wide LCS
    // state machine because the ISD entry's lifecycle byte IS the card LCS in this engine.
    // For SSD and APP entries the OPEN enforces irreversibility of the documented base
    // transitions (5.3.1.2 / 5.3.2.3) and the LOCKED-bit gating from 5.3.1.3 with the GP API
    // privilege rules (lock requires self or Global Lock; unlock requires Global Lock).
    @Override
    public boolean setState(byte newState) {
        var sim = Simulator.current();
        AID callerAID = sim.getAID();
        if (callerAID == null) {
            return false;
        }
        var caller = sim.lookupApplet(callerAID);
        if (caller == null) {
            return false;
        }
        if (this.kind == Kind.ISD) {
            return sim.getGlobalPlatform().setCardLifecycleState(newState);
        }
        int current = this.lifecycle & 0xFF;
        int next = newState & 0xFF;
        if (current == next) {
            return true;
        }
        boolean newLocked = (newState & (byte) 0x80) != 0;
        boolean curLocked = (this.lifecycle & (byte) 0x80) != 0;
        if (newLocked && !curLocked) {
            // GPC v2.3.1 5.3.1.3: lock requires that the caller is the entry itself or holds
            // the Global Lock privilege. The high bit on the new state encodes "lock attempt"
            // per the GPRegistryEntry.setState javadoc; b7..b1 of newState are ignored on lock.
            if (!callerAID.equals(this.aid) && !caller.isPrivileged(GPRegistryEntry.PRIVILEGE_GLOBAL_LOCK)) {
                return false;
            }
            this.lifecycle = (byte) (this.lifecycle | 0x80);
            return true;
        }
        if (!newLocked && curLocked) {
            // GPC v2.3.1 5.3.1.3: only a Global Lock privilege holder may unlock; an applet
            // cannot unlock itself via this path (which is exactly why setCardContentState
            // also forbids self-unlock).
            if (!caller.isPrivileged(GPRegistryEntry.PRIVILEGE_GLOBAL_LOCK)) {
                return false;
            }
            this.lifecycle = (byte) (this.lifecycle & 0x7F);
            return true;
        }
        if (curLocked) {
            // Locked entry receiving another lock-flagged write: javadoc says b7..b1 of newState
            // are ignored, so this is a no-op success.
            return true;
        }
        // GPRegistryEntry.setState javadoc: "If this method is invoked to transition an
        // Application (or Security Domain) from the INSTALLED state to the SELECTABLE state,
        // then the request shall be rejected." (Use INSTALL [for make selectable] instead.)
        if (current == 0x03 && next == 0x07) {
            return false;
        }
        // GPC v2.3.1 5.3.1.2: INSTALLED -> SELECTABLE is irreversible, so reject any regression
        // back to INSTALLED (0x03) or SELECTABLE (0x07) once the entry has moved past them.
        if (next == 0x03 && current > 0x03) {
            return false;
        }
        if (next == 0x07 && current > 0x07) {
            return false;
        }
        // GPC v2.3.1 5.3.2.3: for Security Domains, SELECTABLE -> PERSONALIZED (0x0F) is
        // irreversible, so once at PERSONALIZED or beyond an SSD cannot regress below 0x0F.
        if (this.kind == Kind.SSD && current >= 0x0F && next < 0x0F) {
            return false;
        }
        this.lifecycle = newState;
        return true;
    }

    @Override
    public short getPrivileges(byte[] buf, short off) throws ArrayIndexOutOfBoundsException {
        byte[] bytes = BitField.encode(privileges, 3);
        Util.arrayCopyNonAtomic(bytes, (short) 0, buf, off, (short) bytes.length);
        return (short) (off + bytes.length);
    }

    @Override
    public boolean isPrivileged(byte b) {
        Privilege p = privilegeForByte(b);
        return p != null && privileges.contains(p);
    }

    public EnumSet<Privilege> getPrivileges() {
        return copyPrivileges(privileges);
    }

    public void setPrivileges(EnumSet<Privilege> p) {
        privileges = copyPrivileges(p);
    }

    @Override
    public boolean isAssociated(AID sdAID) {
        return parentSD != null && parentSD.equals(sdAID);
    }

    @Override
    public void registerService(short sServiceName) throws ISOException {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    @Override
    public void deregisterService(short sServiceName) throws ISOException {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    // Map JC GP API privilege byte constants (PRIVILEGE_*) to GPPro Privilege enum values.
    private static Privilege privilegeForByte(byte b) {
        return switch (b) {
            case GPRegistryEntry.PRIVILEGE_SECURITY_DOMAIN -> Privilege.SecurityDomain;
            case GPRegistryEntry.PRIVILEGE_DAP_VERIFICATION -> Privilege.DAPVerification;
            case GPRegistryEntry.PRIVILEGE_DELEGATED_MANAGEMENT -> Privilege.DelegatedManagement;
            case GPRegistryEntry.PRIVILEGE_CARD_LOCK -> Privilege.CardLock;
            case GPRegistryEntry.PRIVILEGE_CARD_TERMINATE -> Privilege.CardTerminate;
            case GPRegistryEntry.PRIVILEGE_CARD_RESET -> Privilege.CardReset;
            case GPRegistryEntry.PRIVILEGE_CVM_MANAGEMENT -> Privilege.CVMManagement;
            case GPRegistryEntry.PRIVILEGE_MANDATED_DAP -> Privilege.MandatedDAPVerification;
            case GPRegistryEntry.PRIVILEGE_TRUSTED_PATH -> Privilege.TrustedPath;
            case GPRegistryEntry.PRIVILEGE_AUTHORIZED_MANAGEMENT -> Privilege.AuthorizedManagement;
            case GPRegistryEntry.PRIVILEGE_TOKEN_VERIFICATION -> Privilege.TokenVerification;
            case GPRegistryEntry.PRIVILEGE_GLOBAL_DELETE -> Privilege.GlobalDelete;
            case GPRegistryEntry.PRIVILEGE_GLOBAL_LOCK -> Privilege.GlobalLock;
            case GPRegistryEntry.PRIVILEGE_GLOBAL_REGISTRY -> Privilege.GlobalRegistry;
            case GPRegistryEntry.PRIVILEGE_FINAL_APPLICATION -> Privilege.FinalApplication;
            case GPRegistryEntry.PRIVILEGE_GLOBAL_SERVICE -> Privilege.GlobalService;
            case GPRegistryEntry.PRIVILEGE_RECEIPT_GENERATION -> Privilege.ReceiptGeneration;
            case GPRegistryEntry.PRIVILEGE_CIPHERED_LOAD_FILE_DATA_BLOCK -> Privilege.CipheredLoadFileDataBlock;
            default -> null;
        };
    }
}
