// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import com.licel.jcardsim.base.JavaCardRuntime;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.*;
import org.bouncycastle.util.encoders.Hex;
import org.globalplatform.Application;
import org.globalplatform.GPRegistryEntry;
import org.globalplatform.GPSystem;
import org.globalplatform.Personalization;
import org.globalplatform.SecureChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.gp.GPCrypto;
import pro.javacard.gp.GPRegistryEntry.Kind;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.data.BitField;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.Tag;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.SortedMap;
import java.util.TreeMap;

// Security Domain applet implementing the GP card manager command set (INSTALL, DELETE, STORE DATA, GET STATUS, GET DATA, SET STATUS, INITIALIZE_UPDATE, EXTERNAL_AUTHENTICATE, PUT KEY). The well-known instance at OPEN_AID is the ISD; future SSD instances reuse this class.
public class SecurityDomainApplet extends Applet {

    private static final Logger log = LoggerFactory.getLogger(SecurityDomainApplet.class);

    // Default ISD privilege profile (GPC v2.3.1 6.6.1 Table 6-1 / 6.6.2), used by the engine bootstrap when planting the ISD entry.
    public static final EnumSet<Privilege> ISD_DEFAULT_PRIVILEGES = EnumSet.of(Privilege.SecurityDomain, Privilege.CardReset, Privilege.CardLock, Privilege.CardTerminate, Privilege.CVMManagement, Privilege.AuthorizedManagement);

    // Factory/bootstrap KVN convention: planted by JavaCardEngine.Builder on a fresh ISD via
    // KeySet.ofMaster((byte) 0xFF, ...). On the first non-factory PUT KEY add to an SD whose
    // only existing KVN is 0xFF, the factory key disappears (engine-defined; GPC v2.3.1 11.8 silent).
    public static final byte FACTORY_KVN = (byte) 0xFF;

    public SecurityDomainApplet() {
    }

    // Standard JC install entry point (GPC v2.3.1 11.5.2 / JCRE Applet contract). Drives the normal
    // Simulator install/register flow for SSDs; the ISD is planted directly by JavaCardEngine.Builder
    // and never reaches this path. Buffer layout is the install_parameters block built by Helpers:
    // [aid_len][aid][priv_len][priv][param_len][params]; we forward the AID slice to register().
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new SecurityDomainApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public static final AID OPEN_AID = AIDUtil.create("A000000151000000");

    // Default SSD package + module AIDs as used by gp-pro --domain (GPTool.java:677-681).
    // GP-spec aligned (GlobalPlatform RID A000000151 + PIX 5350 "SP" / 535041 "SPA").
    public static final AID SSD_PACKAGE_AID = AIDUtil.create("A0000001515350");
    public static final AID SSD_MODULE_AID = AIDUtil.create("A000000151535041");

    private static final byte INS_GET_DATA = (byte) 0xCA;
    private static final byte INS_PUT_KEY = (byte) 0xD8;
    private static final byte INS_STORE_DATA = (byte) 0xE2;
    private static final byte INS_DELETE = (byte) 0xE4;
    private static final byte INS_INSTALL = (byte) 0xE6;
    private static final byte INS_LOAD = (byte) 0xE8;
    private static final byte INS_SET_STATUS = (byte) 0xF0;
    private static final byte INS_GET_STATUS = (byte) 0xF2;

    // GPC v2.3.1 Table 11-5: SSD lifecycle PERSONALIZED encoding.
    private static final byte SSD_PERSONALIZED = (byte) 0x0F;

    // GPC v2.3.1 11.3 GET DATA tags handled by handleGetData. P1P2 of the APDU encodes the tag.
    private static final short TAG_CPLC = (short) 0x9F7F;
    private static final short TAG_KEY_INFORMATION_TEMPLATE = (short) 0x00E0;

    // SW values not present in this project's javacard.framework.ISO7816.
    private static final short SW_REFERENCED_DATA_NOT_FOUND = 0x6A88;
    private static final short SW_RESPONSE_BYTES_REMAINING = 0x6310;
    private static final short SW_FUNC_NOT_SUPPORTED = 0x6A81;

    // INSTALL P1 variants (low 7 bits — b8 = "more INSTALL commands following" is masked off).
    private static final byte P1_INSTALL_FOR_LOAD = (byte) 0x02;
    private static final byte P1_INSTALL_FOR_INSTALL_AND_MAKE_SELECTABLE = (byte) 0x0C;
    private static final byte P1_INSTALL_FOR_EXTRADITION = (byte) 0x10;
    private static final byte P1_INSTALL_FOR_PERSONALIZATION = (byte) 0x20;

    // GET STATUS chunked-response state. The buffer is built on the first call (P2 bit 0 = 0),
    // drained one chunk at a time on continuations (P2 bit 0 = 1), and cleared by any other APDU.
    // Chunk size is the SC's max response payload — varies by SCP variant and R-MAC/R-ENC bits.
    private byte[] pendingStatus;
    private short pendingStatusOffset;
    private byte pendingStatusP1;

    // Target of the next STORE DATA: set by INSTALL [for Personalization], consumed by STORE DATA,
    // cleared on the last STORE DATA block (P1 bit 7), on a missing/invalid target, or by any
    // non-STORE-DATA APDU at the dispatcher (mirrors the pendingStatus hygiene rule).
    private AID personalizationTarget;

    // Per-instance GP data tags written via STORE DATA (no personalization target). Holds non-CPLC
    // tags only; CPLC (9F7F) is card-wide and lives on GlobalPlatform. Tags are packed into int
    // (1, 2, or 3 BER tag bytes, MSB-first).
    private final SortedMap<Integer, byte[]> data = new TreeMap<>();

    // Multi-block STORE DATA accumulation buffer for the GP-data write path.
    // Reset after the last block (P1 bit 7) is committed, or on any non-STORE-DATA APDU.
    private ByteArrayOutputStream storeDataBuffer;

    public byte[] getData(int tag) {
        byte[] v = data.get(tag);
        return v == null ? null : v.clone();
    }

    public void putData(int tag, byte[] value) {
        if (value == null) {
            data.remove(tag);
            return;
        }
        data.put(tag, value.clone());
    }

    // Master keys owned by this Security Domain. Iteration order is PUT KEY insertion order so the
    // IU P1=0 ("any KVN") fallback in primeSecureChannel can pick the most-recently-put keyset
    // (GPC v2.3.1 D.4.1.3 only requires "the first available key chosen by the Security Domain" —
    // implementation-defined). A SortedMap on Byte would order 0xFF before 0x01 — wrong here.
    private final LinkedHashMap<Byte, KeySet> keys = new LinkedHashMap<>();

    public KeySet getKey(byte kvn) {
        return keys.get(kvn);
    }

    public Collection<KeySet> getKeys() {
        return Collections.unmodifiableCollection(keys.values());
    }

    // Structural seed (no factory-key trigger). Used for the ISD bootstrap plant in
    // JavaCardEngine.Builder and for SSD key inheritance in Simulator.internalInstallSSD —
    // both copy keys verbatim rather than personalize. The personalization path (PUT KEY)
    // mutates the map directly in handlePutKey, since the factory-removal trigger is part
    // of PUT KEY semantics, not the storage contract.
    public void seedKey(KeySet keySet) {
        keys.remove(keySet.kvn());
        keys.put(keySet.kvn(), keySet);
    }

    // GPC v2.3.1 11.9.3.1 / ISO 7816-4 5.3.4: minimal SD SELECT response.
    //   6F LL { 84 LA <aid> | A5 04 { 9F 65 01 FF } }
    static byte[] fci(AID aid) {
        return TLV.build(Tag.ber(0x6F))
                .add(Tag.ber(0x84), AIDUtil.bytes(aid))
                .add(TLV.build(Tag.ber(0xA5))
                        .add(Tag.ber(0x9F65), new byte[]{(byte) 0xFF}))
                .encode();
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        var sc = Simulator.current().getGlobalPlatform().getSecureChannel();

        // Any APDU that is not a GET STATUS continuation invalidates the pending response.
        if (ins != INS_GET_STATUS || (buffer[ISO7816.OFFSET_P2] & 0x01) == 0) {
            pendingStatus = null;
        }

        // Any APDU that is not a STORE DATA invalidates a pending personalization sequence
        // and any partial GP-data write accumulation.
        if (ins != INS_STORE_DATA) {
            personalizationTarget = null;
            storeDataBuffer = null;
        }

        if (selectingApplet()) {
            // GPC v2.3.1 11.9.3.1 / ISO 7816-4 5.3.4: minimal SELECT FCI for the SD instance.
            byte[] fci = fci(JCSystem.getAID());
            Util.arrayCopyNonAtomic(fci, (short) 0, buffer, (short) 0, (short) fci.length);
            apdu.setOutgoingAndSend((short) 0, (short) fci.length);
            // GPC v2.3.1 11.9.3.2 / Table 11-83: SELECT may return warning SW '62' '83' when the
            // Security Domain with the Final Application privilege is being selected and the Card
            // Life Cycle State is CARD_LOCKED. The FCI is still returned with the warning SW.
            var caller = Simulator.current().lookupApplet(JCSystem.getAID());
            if (caller != null && caller.isPrivileged(GPRegistryEntry.PRIVILEGE_FINAL_APPLICATION)
                    && Simulator.current().getGlobalPlatform().getCardState() == GPSystem.CARD_LOCKED) {
                ISOException.throwIt((short) 0x6283);
            }
            return;
        }

        if (ins == EngineSecureChannel.INS_INITIALIZE_UPDATE || ins == EngineSecureChannel.INS_EXTERNAL_AUTHENTICATE) {
            // INITIALIZE_UPDATE primes the SC with master keys looked up on the ISD entry.
            // EXTERNAL_AUTHENTICATE re-uses the keys primed at IU; no re-priming needed.
            if (ins == EngineSecureChannel.INS_INITIALIZE_UPDATE) {
                primeSecureChannel(buffer[ISO7816.OFFSET_P1]);
            }
            short len = sc.processSecurity(apdu);
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
            return;
        }

        // GET DATA is treated as unauthenticated by this engine because CPLC and KIT are public
        // information probeable before SCP comes up, and GPC v2.3.1 11.3 does not mandate auth
        // either way. The command is dispatched before the auth gate and without unwrap() so
        // clients send GET DATA plain.
        if (ins == INS_GET_DATA) {
            apdu.setIncomingAndReceive();
            handleGetData(apdu, buffer);
            return;
        }

        if ((sc.getSecurityLevel() & SecureChannel.AUTHENTICATED) != SecureChannel.AUTHENTICATED) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        short len = apdu.setIncomingAndReceive();
        sc.unwrap(buffer, ISO7816.OFFSET_CLA, (short) (ISO7816.OFFSET_CDATA + len));
        byte[] payload = Arrays.copyOfRange(buffer, ISO7816.OFFSET_CDATA, ISO7816.OFFSET_CDATA + (buffer[ISO7816.OFFSET_LC] & 0xFF));

        // Variant handlers may bubble IllegalArgumentException from AIDUtil.create or parse_lv
        // when the client sends malformed data — funnel all such cases to SW_WRONG_DATA here
        // instead of catching at every call site.
        try {
            switch (ins) {
                case INS_INSTALL -> handleInstall(apdu, buffer, payload);
                case INS_STORE_DATA -> handleStoreData(apdu, buffer, payload);
                case INS_DELETE -> handleDelete(apdu, buffer, payload);
                case INS_PUT_KEY -> handlePutKey(apdu, buffer, payload);
                case INS_SET_STATUS -> handleSetStatus(apdu, buffer, payload);
                case INS_GET_STATUS -> handleGetStatus(apdu, buffer);
                // GPC v2.3.1 11.6: LOAD carries CAP-file blocks during on-card loading. The engine
                // plants load files synthetically (Simulator.loadApplet); on-card loading is
                // unsupported by design, so the LOAD APDU is actively rejected.
                case INS_LOAD -> ISOException.throwIt(SW_FUNC_NOT_SUPPORTED);
                default -> ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (IllegalArgumentException e) {
            log.warn("Malformed APDU data: {}", e.getMessage());
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }

    // Walk the SD chain from `entry` upward, returning the first non-empty *own* keyset found.
    // Non-SD entries (PKG/APP) carry no keys and are naturally skipped. Termination: ISD (self-parent)
    // or a missing parent. The ISD is always seeded by JavaCardEngine.Builder, so the walk effectively
    // always terminates with a result. Empty result is only possible if the registry is malformed.
    //
    // This implements the spec semantics: an SSD without own keys delegates to its associated SD;
    // there is no key copying. If the parent's keys later change (e.g. ISD rotates KVN=0xFF), the
    // SSD's authentication immediately follows.
    static Collection<KeySet> resolveKeys(JavaCardRuntime sim, EngineRegistryEntry entry) {
        while (entry != null) {
            if (entry.getApplet() instanceof SecurityDomainApplet sda && !sda.keys.isEmpty()) {
                return sda.getKeys();
            }
            var parentAid = entry.getParentSD();
            if (parentAid == null || parentAid.equals(entry.getAID())) {
                break;
            }
            entry = sim.lookupApplet(parentAid);
        }
        return List.of();
    }

    // Look up the master key set used for this SD's INITIALIZE_UPDATE (P1 = requested KVN, 0 = any).
    // Resolution: own keys if any, else walk parent chain (resolveKeys). For P1=0, picks the most
    // recently put keyset (newest wins); GPC v2.3.1 D.4.1.3 only requires "the first available key
    // chosen by the Security Domain" — implementation-defined.
    private void primeSecureChannel(byte requestedKvn) {
        var sim = Simulator.current();
        var resolved = resolveKeys(sim, sim.lookupApplet(JCSystem.getAID()));
        KeySet ks;
        if (requestedKvn == 0) {
            // "Newest wins" = LinkedHashMap insertion-order tail of the resolved SD.
            ks = resolved.stream().reduce((a, b) -> b).orElse(null);
            if (ks == null) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        } else {
            ks = resolved.stream().filter(k -> k.kvn() == requestedKvn).findFirst().orElse(null);
            if (ks == null) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
        }
        sim.getGlobalPlatform().getSecureChannel().beginSession(ks);
    }

    // INSTALL dispatch. All supported variants share a 6-LV field contract per the per-variant
    // tables below: GPC v2.3.1 11.5.2.3.2 / Table 11-43 covers install, 11.5.2.3.4 / Table 11-45
    // covers extradition, and 11.5.2.3.6 / Table 11-47 covers personalization. P1 b8 is the
    // orthogonal "more INSTALL commands following" marker, so mask it off before dispatch.
    private static final int INSTALL_LV_FIELD_COUNT = 6;

    private void handleInstall(APDU apdu, byte[] buffer, byte[] payload) {
        byte p1 = (byte) (buffer[ISO7816.OFFSET_P1] & 0x7F);

        // GPC v2.3.1 11.5.2.1 / Table 11-41: P1 b2 (0x02) = "For load". Engine plants load files synthetically
        // (Simulator.loadApplet); on-card loading is unsupported by design. Any P1 carrying the
        // load bit — INSTALL [for load] (0x02) or composites like [for load+install+make selectable]
        // (0x0E) — is rejected before LV parsing, since load-variant payloads have a different shape.
        if ((p1 & P1_INSTALL_FOR_LOAD) != 0) {
            log.warn("INSTALL [for load] (P1=0x{}): on-card loading not supported", String.format("%02X", buffer[ISO7816.OFFSET_P1] & 0xFF));
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED);
        }

        var fields = parse_lv(payload);
        dump_lv(fields);

        if (fields.size() != INSTALL_LV_FIELD_COUNT) {
            throw new IllegalArgumentException("INSTALL: expected " + INSTALL_LV_FIELD_COUNT + " LV fields, got " + fields.size());
        }

        switch (p1) {
            case P1_INSTALL_FOR_PERSONALIZATION -> installForPersonalization(apdu, buffer, fields);
            case P1_INSTALL_FOR_INSTALL_AND_MAKE_SELECTABLE -> installForInstallAndMakeSelectable(apdu, buffer, fields);
            case P1_INSTALL_FOR_EXTRADITION -> installForExtradition(apdu, buffer, fields);
            default -> {
                log.warn("INSTALL: unsupported P1=0x%02X".formatted(buffer[ISO7816.OFFSET_P1] & 0xFF));
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
        }
    }

    // INSTALL [for Personalization] — sets the STORE DATA target on the OPEN.
    // Field layout (GPC v2.3.1 11.5.2.3.6, Table 11-47): empty | empty | Application AID | empty | empty | empty.
    private void installForPersonalization(APDU apdu, byte[] buffer, List<byte[]> fields) {
        var targetAid = AIDUtil.create(fields.get(2));
        var instance = Simulator.current().lookupApplet(targetAid);
        if (instance == null) {
            log.warn("Personalization target applet not found: {}", AIDUtil.toString(targetAid));
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        Applet target = instance.getApplet();
        if (!(target instanceof Personalization) && !(target instanceof Application)) {
            log.warn("Target applet does not implement Personalization or Application interface");
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        personalizationTarget = targetAid;
        buffer[0] = 0x00;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    // INSTALL [for Install (and Make Selectable)] — instantiates an applet from a loaded package.
    // Field layout (GPC v2.3.1 11.5.2.3.2, Table 11-43): ELF AID | Module AID | App AID | Privileges | Install Params | Token.
    //
    // SSDs and APP applets share this path: both go through Simulator.internalInstallApplet, which
    // invokes the static install() method and lets the resulting register() callback build the
    // registry entry. SSDs differ in two pre-checks (GP-correct SW mapping for duplicate AIDs and
    // privilege/Kind coherence) and in the `exposed` flag — the SD class is platform code and must
    // not be reloaded into an isolated classloader. New SSDs start with empty keys and authenticate
    // via parent walk-up (resolveKeys) until the SSD owner runs PUT KEY for its own keys.
    private void installForInstallAndMakeSelectable(APDU apdu, byte[] buffer, List<byte[]> fields) {
        var sim = Simulator.current();
        var pkg = AIDUtil.create(fields.get(0));
        var app = AIDUtil.create(fields.get(1));
        var instanceAid = AIDUtil.create(fields.get(2));
        var privileges = fields.get(3);
        var parameters = fields.get(4);
        var appletClass = sim.getGlobalPlatform().locateApplet(pkg, app);

        if (appletClass == null) {
            log.warn("Applet not found");
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        boolean isSD = appletClass == SecurityDomainApplet.class;
        if (isSD) {
            // GP-correct SW mapping: register() throws SystemException.ILLEGAL_AID on duplicate,
            // which internalInstallApplet swallows into JavaCardEngineException — pre-check here
            // to return the spec-mandated 0x6985 cleanly.
            if (sim.lookupApplet(instanceAid) != null) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            // EngineRegistryEntry.forApplet auto-derives Kind from the privilege bit; without
            // SecurityDomain set the entry would register as Kind.APP backed by an SDA instance
            // — incoherent state.
            if (!EngineRegistryEntry.decodePrivileges(privileges).contains(Privilege.SecurityDomain)) {
                log.warn("SSD install requires SecurityDomain privilege");
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }

        // Install parameters carry a C9-tagged inner block — that's what the applet actually receives.
        if (parameters.length > 0) {
            TLV c9 = TLV.find(TLV.parse(parameters), Tag.ber(0xC9)).orElse(null);
            parameters = c9 != null ? c9.value() : new byte[0];
        }
        // exposed=true for the SD class: it's platform code that touches Simulator/GP statics and
        // must not be reloaded into an isolated classloader.
        sim.internalInstallApplet(instanceAid, appletClass, privileges, parameters, isSD, pkg);
        buffer[0] = 0x00;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    // INSTALL [for extradition] — rebind an existing APP/SSD/PKG entry to a new associated SD
    // (GPC v2.3.1 11.5.2.3.4 / Table 11-45). Field layout matches what gp-pro's GPSession.extradite
    // writes: 5 LV fields built by extradite() plus 1 Token byte appended by DMTokenizer = 6 fields.
    //   [0] new SD AID
    //   [1] empty
    //   [2] App or ELF AID
    //   [3] empty (params)
    //   [4] empty
    //   [5] empty (token slot)
    // The first AID is the *new* SD; the second is the entity being extradited.
    //
    // Privilege gate: the SD performing the command must hold AuthorizedManagement or
    // DelegatedManagement (GPC v2.3.1 9.4.1 Content Extradition; AM/DM defined in 9.1.3.2/3 and
    // Table 6-1 / 6.6.1). The ISD has AM by default; SSDs need explicit grant.
    private void installForExtradition(APDU apdu, byte[] buffer, List<byte[]> fields) {
        var sim = Simulator.current();
        var caller = sim.lookupApplet(sim.getAID());
        if (caller == null || (!caller.isPrivileged(GPRegistryEntry.PRIVILEGE_AUTHORIZED_MANAGEMENT) && !caller.isPrivileged(GPRegistryEntry.PRIVILEGE_DELEGATED_MANAGEMENT))) {
            log.warn("INSTALL [for extradition]: caller {} lacks AM/DM privilege", caller == null ? "null" : AIDUtil.toString(caller.getAID()));
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        var newSD = AIDUtil.create(fields.get(0));
        var target = AIDUtil.create(fields.get(2));

        // Pre-validate so we can map specific failure modes to GP-correct SWs (the simulator's
        // generic IllegalArgumentException would funnel everything to SW_WRONG_DATA).
        if (target.equals(newSD)) {
            log.warn("INSTALL [for extradition]: self-extradition rejected: {}", AIDUtil.toString(target));
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        var newSDEntry = sim.lookupApplet(newSD);
        if (newSDEntry == null || (newSDEntry.getKind() != Kind.ISD && newSDEntry.getKind() != Kind.SSD)) {
            log.warn("INSTALL [for extradition]: new SD {} not found or not an SD", AIDUtil.toString(newSD));
            ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
        }
        var targetEntry = sim.lookupApplet(target);
        if (targetEntry == null) {
            targetEntry = sim.getGlobalPlatform().getPackage(target);
        }
        if (targetEntry == null) {
            log.warn("INSTALL [for extradition]: target {} not found", AIDUtil.toString(target));
            ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
        }
        if (targetEntry.getKind() == Kind.ISD) {
            log.warn("INSTALL [for extradition]: ISD cannot be extradited");
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // After this rebind, EngineSecureChannel.resolveMasterKey()'s chain-walk and the
        // primeSecureChannel walk-up will reach the new SD instead of the old one.
        targetEntry.setParentSD(newSD);
        log.info("Extradited {} to SD {}", AIDUtil.toString(target), AIDUtil.toString(newSD));
        buffer[0] = 0x00;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    // STORE DATA — two roles:
    //   1) Indirect personalization: payload forwarded to the AID set by INSTALL [for Personalization].
    //      Personalization and Application both extend javacard.framework.Shareable, so
    //      JavaCardRuntime.getInterface() returns a context-switching proxy. GPC v2.3.1 7.3.2:
    //      "the command is forwarded to the Application by the GlobalPlatform Trusted Framework
    //      which handles inter-application communication between Security Domains and Applications."
    //   2) GP data write: when no personalization target is set, the payload is BER-TLV encoded
    //      card data (GPC v2.3.1 11.11). Tags 9F66 / 9F67 update CPLC slices on GlobalPlatform;
    //      9F7F is rejected (CPLC is read-only as a whole); other tags land in this SD's
    //      per-instance store. SCP authentication is enforced by the wrapper above this method.
    private void handleStoreData(APDU apdu, byte[] buffer, byte[] payload) {
        if (personalizationTarget == null) {
            handleStoreGPData(apdu, buffer, payload);
            return;
        }
        AID targetAid = personalizationTarget;
        var sim = Simulator.current();

        // Build full STORE DATA command: CLA + INS + P1 + P2 + Lc + data
        short cmdLen = (short) (ISO7816.OFFSET_CDATA + payload.length);
        byte[] cmdBuffer = new byte[cmdLen];
        Util.arrayCopyNonAtomic(buffer, (short) 0, cmdBuffer, (short) 0, cmdLen);

        boolean lastBlock = (buffer[ISO7816.OFFSET_P1] & (byte) 0x80) != 0;

        var perso = sim.getInterface(targetAid, Personalization.class);
        if (perso != null) {
            byte[] outBuffer = new byte[256];
            short outLen = perso.processData(cmdBuffer, (short) 0, cmdLen, outBuffer, (short) 0);
            if (lastBlock) {
                personalizationTarget = null;
            }
            if (outLen > 0) {
                Util.arrayCopyNonAtomic(outBuffer, (short) 0, buffer, (short) 0, outLen);
                apdu.setOutgoingAndSend((short) 0, outLen);
            } else {
                buffer[0] = 0x00;
                apdu.setOutgoingAndSend((short) 0, (short) 1);
            }
            return;
        }
        var app = sim.getInterface(targetAid, Application.class);
        if (app != null) {
            app.processData(cmdBuffer, (short) 0, cmdLen);
            if (lastBlock) {
                personalizationTarget = null;
            }
            buffer[0] = 0x00;
            apdu.setOutgoingAndSend((short) 0, (short) 1);
            return;
        }
        log.warn("STORE DATA: target {} not found or does not implement Personalization/Application", AIDUtil.toString(targetAid));
        personalizationTarget = null;
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // GP-data write path: accumulate payload across blocks, parse as BER-TLV on the last block.
    // P1 format bits (0x18): 00 (no info, used by gp-pro --set-perso/--set-pre-perso) and 10 (BER-TLV)
    // both yield identical wire form for the tags we care about. 11 (encrypted) is rejected.
    private void handleStoreGPData(APDU apdu, byte[] buffer, byte[] payload) {
        byte p1 = buffer[ISO7816.OFFSET_P1];
        int format = p1 & 0x18;
        if (format == 0x18) {
            log.warn("STORE DATA: encrypted BER-TLV format not supported (P1=0x{})", String.format("%02X", p1 & 0xFF));
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (storeDataBuffer == null) {
            storeDataBuffer = new ByteArrayOutputStream();
        }
        storeDataBuffer.write(payload, 0, payload.length);
        if ((p1 & 0x80) != 0) {
            commitStoreGPData();
        }
        buffer[0] = 0x00;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    private void commitStoreGPData() {
        byte[] all = storeDataBuffer.toByteArray();
        storeDataBuffer = null;
        byte[] cplc = Simulator.current().getGlobalPlatform().cplc;
        for (TLV tlv : TLV.parse(all)) {
            int tag = tagToInt(tlv.tag());
            byte[] value = tlv.value();
            switch (tag) {
                case 0x9F66 -> writeCPLCSlice(cplc, 34, value);  // perso slice
                case 0x9F67 -> writeCPLCSlice(cplc, 26, value);  // pre-perso slice
                case 0x9F7F -> {                                 // full CPLC overwrite is not allowed
                    log.warn("STORE DATA: CPLC (9F7F) is read-only; use 9F66 / 9F67 for slice updates");
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                default -> putData(tag, value);
            }
        }
    }

    private static void writeCPLCSlice(byte[] cplc, int offset, byte[] value) {
        if (value == null || value.length != 8) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        System.arraycopy(value, 0, cplc, offset, 8);
    }

    // Pack a 1..3-byte BER tag into an int (MSB-first), matching the int keys used in `data`.
    private static int tagToInt(Tag tag) {
        int v = 0;
        for (byte b : tag.bytes()) {
            v = (v << 8) | (b & 0xFF);
        }
        return v;
    }

    // DELETE dispatch (GPC v2.3.1 11.2). The variant is identified by the leading TLV tag in the
    // data field — there is no P1/P2 flag distinguishing them:
    //   '4F'        -> DELETE [card content] (Table 11-23) — applet/load file by AID.
    //   'D0' / 'D2' -> DELETE [key] (Table 11-24) — keyset by Key Identifier / Key Version Number.
    private void handleDelete(APDU apdu, byte[] buffer, byte[] payload) {
        var tlvs = TLV.parse(payload);

        var d0 = TLV.find(tlvs, Tag.ber(0xD0)).orElse(null);
        var d2 = TLV.find(tlvs, Tag.ber(0xD2)).orElse(null);
        if (d0 != null || d2 != null) {
            handleDeleteKey(apdu, buffer, d0, d2);
            return;
        }

        // DELETE [card content] (Table 11-23): '4F' Lc AID [further CRT tags...].
        var aidTlv = TLV.find(tlvs, Tag.ber(0x4F)).orElse(null);
        if (aidTlv == null) {
            log.warn("DELETE: missing 4F AID tag");
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }
        var aid = AIDUtil.create(aidTlv.value());
        try {
            Simulator.current().internalDeleteApplet(aid);
        } catch (IllegalArgumentException e) {
            log.warn("DELETE: {}", e.getMessage());
            ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
        }
        buffer[0] = 0x00;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    // DELETE [key] (GPC v2.3.1 11.2.2.3.2, Table 11-24).
    //   'D0' (Key Identifier)     1 byte
    //   'D2' (Key Version Number) 1 byte
    // Spec semantics:
    //   D0 + D2 -> single specific key inside the keyset for that KVN
    //   D2 only -> entire keyset for that KVN
    //   D0 only -> all keys with that KID across all KVNs
    // Engine model: each KVN maps to one ENC/MAC/DEK triple stored atomically — per-KID deletion
    // would leave a malformed keyset. Therefore this engine supports only the "D2 only -> drop the
    // whole KVN" form and rejects D0 (with or without D2) as unsupported.
    private void handleDeleteKey(APDU apdu, byte[] buffer, TLV d0, TLV d2) {
        if (d0 != null) {
            log.warn("DELETE [key] with Key Identifier ('D0') is not supported by this engine; deletion grain is per-KVN");
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED);
        }
        if (d2.value().length != 1) {
            log.warn("DELETE [key]: 'D2' tag must be 1 byte, got {}", d2.value().length);
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        byte kvn = d2.value()[0];

        // DELETE [key] (GPC v2.3.1 11.2.2.3.2): remove the entire keyset for the given KVN. The
        // engine's KeySet model holds an ENC/MAC/DEK triple atomically; per-KID deletion is not
        // representable, so deletion grain is per-KVN (D0-only requests are rejected above).
        if (keys.remove(kvn) == null) {
            log.warn("DELETE [key]: no keyset for KVN=0x{}", String.format("%02X", kvn & 0xFF));
            ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
        }

        // Table 11-25 / 11.2.3.1: a single 0x00 length-of-confirmation byte is returned.
        buffer[0] = 0x00;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    // PUT KEY (GPC v2.3.1 11.8). P1 = 0 to add a new KVN, or KVN to replace an existing one.
    // P2 low 7 bits = first KID; bit 7 = "more than one key in this command" — gp-pro always
    // sends 0x81 (KID 0x01 ENC + flag) and ships the ENC/MAC/DEK triple in one APDU. Body is
    // [new_KVN] [block_ENC] [block_MAC] [block_DEK] where each block is type-prefixed
    // [0x88 (AES) | block_len | actual_key_len | cgram | kcv_len | kcv]
    // [0x80 (DES3) | block_len | cgram | kcv_len | kcv].
    // Response is [new_KVN | KCV_KID1 | KCV_KID2 | KCV_KID3] (3 bytes per KCV).
    private void handlePutKey(APDU apdu, byte[] buffer, byte[] payload) {
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];
        if ((p2 & 0x80) == 0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        byte firstKid = (byte) (p2 & 0x7F);
        if (firstKid != KeySet.KID_ENC) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        var bb = ByteBuffer.wrap(payload);
        if (!bb.hasRemaining()) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // GPC defines the PUT KEY KVN range as 0x01..0x7F. 0x00 is reserved (KVN-as-flag),
        // 0x80..0xFE are out of range, and 0xFF is the ISD factory/bootstrap slot — planted at
        // boot via seedKey and only ever evicted by the factory-removal trigger below. PUT KEY
        // never installs 0xFF: SSDs without own keys delegate to their parent (resolveKeys),
        // which reaches the ISD's 0xFF as long as it still exists.
        byte newKvn = bb.get();
        int kvnUnsigned = newKvn & 0xFF;
        if (kvnUnsigned < 0x01 || kvnUnsigned > 0x7F) {
            log.warn("PUT KEY: KVN 0x{} out of range 0x01..0x7F", String.format("%02X", kvnUnsigned));
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        var sd = Simulator.current().lookupApplet(JCSystem.getAID());

        if (p1 == 0) {
            if (getKey(newKvn) != null) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        } else {
            if (p1 != newKvn) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            if (getKey(p1) == null) {
                ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
            }
        }

        var sc = Simulator.current().getGlobalPlatform().getSecureChannel();
        var entries = new TreeMap<Byte, KeySet.KeyEntry>();
        var kcvOut = new ByteArrayOutputStream();
        kcvOut.write(newKvn & 0xFF);

        for (byte kid = KeySet.KID_ENC; kid <= KeySet.KID_DEK; kid++) {
            entries.put(kid, parseKeyBlock(bb, sc, payload, kcvOut));
        }
        if (bb.hasRemaining()) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Factory-key removal trigger: if this SD currently holds ONLY the factory KVN=0xFF and
        // we are adding a different KVN (the first owner-personalization), the factory key
        // disappears. GPC v2.3.1 11.8 categorises PUT KEY as replace/add but is silent on a
        // factory-removal trigger; this is an engine-defined convention. Same-KVN replace
        // (newKvn == 0xFF) does NOT trigger; coexistence with non-factory KVNs (size > 1) does NOT trigger.
        if (newKvn != FACTORY_KVN
                && keys.size() == 1
                && keys.containsKey(FACTORY_KVN)) {
            keys.remove(FACTORY_KVN);
        }
        // Remove first so a re-put of an existing KVN moves it to the end (becomes newest).
        // LinkedHashMap.put(k, v) does NOT change iteration order if k already exists.
        keys.remove(newKvn);
        keys.put(newKvn, new KeySet(newKvn, entries));

        // GPC v2.3.1 11.1.1 Table 11-5: an SSD becomes PERSONALIZED on its first PUT KEY (owner now
        // has its own keys instead of resolving via parent). Transition fires once, while SELECTABLE.
        // The ISD does not transition on PUT KEY — its lifecycle is the card LCS, driven by SET STATUS.
        if (sd.getKind() == Kind.SSD && sd.getState() == EngineRegistryEntry.APP_SELECTABLE) {
            sd.setState(SSD_PERSONALIZED);
        }

        byte[] response = kcvOut.toByteArray();
        Util.arrayCopyNonAtomic(response, (short) 0, buffer, (short) 0, (short) response.length);
        apdu.setOutgoingAndSend((short) 0, (short) response.length);
    }

    // Parse one PUT KEY block, decrypt the cgram in place via the active SC's decryptData
    // (uses session DEK on SCP02, static DEK on SCP03), verify the on-wire KCV against the
    // re-computed one, and append the 3-byte KCV to the response under construction.
    private static KeySet.KeyEntry parseKeyBlock(ByteBuffer bb, EngineSecureChannel sc, byte[] payload, ByteArrayOutputStream kcvOut) {
        if (bb.remaining() < 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        byte type = bb.get();
        int blockLen = bb.get() & 0xFF;

        int actualKeyLen;
        int cgramLen;
        if (type == KeySet.TYPE_AES) {
            // GPC v2.3.1 11.8.2.3.2 / Table 11-70 ("Format of Key Component Block - Padding Present"):
            // blockLen = cgramLen + 1 (the +1 is the actual_key_len byte preceding the encrypted block).
            if (blockLen < 1) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            if (!bb.hasRemaining()) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            actualKeyLen = bb.get() & 0xFF;
            cgramLen = blockLen - 1;
        } else if (type == KeySet.TYPE_DES3) {
            // GPC v2.3.1 11.8.2.3.2 / Table 11-71 ("Format of Key Component Block - Padding Not Present"):
            // plaintext is the full block, no length prefix.
            cgramLen = blockLen;
            actualKeyLen = blockLen;
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return null;
        }

        if (bb.remaining() < cgramLen + 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // bb wraps payload directly, so bb.position() is the index into payload.
        int off = bb.position();
        sc.decryptData(payload, (short) off, (short) cgramLen);
        byte[] keyValue = Arrays.copyOfRange(payload, off, off + actualKeyLen);
        bb.position(off + cgramLen);

        int kcvLen = bb.get() & 0xFF;
        if (bb.remaining() < kcvLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        byte[] wireKcv = new byte[kcvLen];
        bb.get(wireKcv);

        if (kcvLen > 0) {
            byte[] computed = type == KeySet.TYPE_AES ? GPCrypto.kcv_aes(keyValue) : GPCrypto.kcv_3des(keyValue);
            if (kcvLen > computed.length || !Arrays.equals(wireKcv, 0, kcvLen, computed, 0, kcvLen)) {
                log.warn("PUT KEY: KCV mismatch");
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            kcvOut.writeBytes(Arrays.copyOf(computed, 3));
        } else {
            // No KCV on the wire — emit zeros to keep the response shape stable.
            kcvOut.writeBytes(new byte[3]);
        }
        return new KeySet.KeyEntry(type, keyValue);
    }

    // SET STATUS — only P1=0x80 (ISD/card lifecycle) is implemented. Application-LCS path
    // (P1=0x40) is a different state machine and out of scope here. Per GPC v2.3.1 11.10
    // (Table 11-86), the new lifecycle state is in P2; no command data is sent (case-1).
    private void handleSetStatus(APDU apdu, byte[] buffer, byte[] payload) {
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];
        if (p1 != (byte) 0x80) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        if (payload.length != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        boolean ok = Simulator.current().getGlobalPlatform().setCardLifecycleState(p2);
        if (!ok) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        buffer[0] = 0x00;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    // GPC v2.3.1 11.4: tagged GET STATUS only. P1 selects scope (ISD/APP/PKG-no-modules/PKG-with-modules).
    // P2 bit 1 must be set (we don't support legacy non-tagged form). P2 bit 0 = continuation.
    // Long responses are split into chunks sized to the SC's max response payload; intermediate
    // chunks return SW=0x6310.
    private void handleGetStatus(APDU apdu, byte[] buffer) {
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];

        if ((p2 & 0x02) == 0) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        boolean continuation = (p2 & 0x01) != 0;
        if (continuation) {
            if (pendingStatus == null || pendingStatusP1 != p1) {
                pendingStatus = null;
                ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
            }
        } else {
            byte[] full = buildStatusResponse(p1);
            if (full.length == 0) {
                ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
            }
            pendingStatus = full;
            pendingStatusOffset = 0;
            pendingStatusP1 = p1;
        }

        short chunk = Simulator.current().getGlobalPlatform().getSecureChannel().maxResponseLength();
        short remaining = (short) (pendingStatus.length - pendingStatusOffset);
        short toSend = remaining > chunk ? chunk : remaining;
        Util.arrayCopyNonAtomic(pendingStatus, pendingStatusOffset, buffer, (short) 0, toSend);
        pendingStatusOffset += toSend;

        boolean more = pendingStatusOffset < (short) pendingStatus.length;
        apdu.setOutgoingAndSend((short) 0, toSend);
        if (more) {
            ISOException.throwIt(SW_RESPONSE_BYTES_REMAINING);
        }
        pendingStatus = null;
    }

    // GPC v2.3.1 11.3: GET DATA returns a TLV-encoded data item identified by P1P2 (the tag).
    // Responses for CPLC and a single-key-set KIT fit one APDU; no chunking needed yet.
    // CPLC (9F7F) delegates to GlobalPlatform — card-wide data; everything else looks up the
    // SD's per-instance store. Tags written via STORE DATA become readable here automatically.
    private void handleGetData(APDU apdu, byte[] buffer) {
        int tag = Util.makeShort(buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]) & 0xFFFF;
        byte[] response;
        if (tag == (TAG_KEY_INFORMATION_TEMPLATE & 0xFFFF)) {
            response = keyInformationTemplate();
        } else if (tag == (TAG_CPLC & 0xFFFF)) {
            response = TLV.of(Tag.ber(0x9F7F), Simulator.current().getGlobalPlatform().cplc).encode();
        } else {
            byte[] stored = getData(tag);
            if (stored == null) {
                log.warn("GET DATA: unsupported tag 0x%04X".formatted(tag));
                ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
                return;
            }
            response = TLV.of(Tag.ber(tag), stored).encode();
        }
        Util.arrayCopyNonAtomic(response, (short) 0, buffer, (short) 0, (short) response.length);
        apdu.setOutgoingAndSend((short) 0, (short) response.length);
    }

    // GPC v2.3.1 11.3.3.1.1 (Table 11-28): 'E0' Key Information Template wrapping one C0 per (KID, KVN).
    private byte[] keyInformationTemplate() {
        var entries = getKeys().stream().flatMap(ks -> ks.keyInfoEntries().stream()).toList();
        return TLV.of(Tag.ber(0x00E0), entries).encode();
    }

    // Build the full GET STATUS response (concatenated E3 templates) for the given P1.
    private static byte[] buildStatusResponse(byte p1) {
        var sim = Simulator.current();
        var bo = new ByteArrayOutputStream();

        switch (p1 & 0xFF) {
            case 0x80 ->
                    sim.getApplets().stream().filter(e -> e.getKind() == Kind.ISD).forEach(e -> bo.writeBytes(encodeAppletEntry(e)));
            case 0x40 ->
                    sim.getApplets().stream().filter(e -> e.getKind() == Kind.APP || e.getKind() == Kind.SSD).forEach(e -> bo.writeBytes(encodeAppletEntry(e)));
            case 0x20 ->
                    sim.getGlobalPlatform().getPackages().forEach(e -> bo.writeBytes(encodePackageEntry(e, false)));
            case 0x10 -> sim.getGlobalPlatform().getPackages().forEach(e -> bo.writeBytes(encodePackageEntry(e, true)));
            default -> ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        return bo.toByteArray();
    }

    private static byte[] encodeAppletEntry(EngineRegistryEntry e) {
        var tlv = TLV.build(Tag.ber(0xE3)).add(Tag.ber(0x4F), AIDUtil.bytes(e.getAID())).addByte(Tag.ber(0x9F70), e.getState()).add(Tag.ber(0xC5), BitField.encode(e.getPrivileges(), 3));
        AID pkg = e.getPackageAID();
        if (pkg != null) {
            tlv.add(Tag.ber(0xC4), AIDUtil.bytes(pkg));
        }
        // GPC v2.3.1 11.4.3.1 / Table 11-36: tag 'CC' = Associated Security Domain's AID. Surfacing it lets
        // off-card readers track INSTALL [for install] / [for extradition] association flips.
        // forISD/forApplet always set a non-null parent (ISD self-parents) so emit unconditionally.
        tlv.add(Tag.ber(0xCC), AIDUtil.bytes(e.getParentSD()));
        return tlv.encode();
    }

    private static byte[] encodePackageEntry(EngineRegistryEntry e, boolean withModules) {
        var tlv = TLV.build(Tag.ber(0xE3)).add(Tag.ber(0x4F), AIDUtil.bytes(e.getAID())).addByte(Tag.ber(0x9F70), e.getState());
        if (withModules) {
            for (var moduleAid : e.getModules().keySet()) {
                tlv.add(Tag.ber(0x84), AIDUtil.bytes(moduleAid));
            }
        }
        // GPC v2.3.1 11.4.3.1 / Table 11-37: tag 'CC' = Associated Security Domain's AID for Executable Load Files.
        // forPackage always sets a non-null associated SD so emit unconditionally.
        tlv.add(Tag.ber(0xCC), AIDUtil.bytes(e.getParentSD()));
        return tlv.encode();
    }

    static List<byte[]> parse_lv(byte[] data) {
        var result = new ArrayList<byte[]>();
        var bb = ByteBuffer.wrap(data);
        while (bb.position() < bb.limit()) {
            int len = bb.get() & 0xFF;
            if (bb.remaining() < len) {
                throw new IllegalArgumentException("LV truncated: length " + len + " exceeds remaining " + bb.remaining());
            }
            var value = new byte[len];
            bb.get(value);
            result.add(value);
        }
        return result;
    }

    static void dump_lv(List<byte[]> lv) {
        for (var f : lv) {
            log.info("[%02X] %s".formatted(f.length, Hex.toHexString(f)));
        }
    }
}
