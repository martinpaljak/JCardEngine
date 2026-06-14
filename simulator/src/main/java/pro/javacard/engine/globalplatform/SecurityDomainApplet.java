// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.*;
import org.bouncycastle.util.encoders.Hex;
import org.globalplatform.*;
import org.globalplatform.contactless.CLAppletEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.engine.globalplatform.GPNamedElement.GPInfo;
import pro.javacard.engine.globalplatform.GPNamedElement.GPTag;
import pro.javacard.gp.GPCrypto;
import pro.javacard.gp.GPRegistryEntry.Kind;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.data.BitField;
import pro.javacard.tlv.LV;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.TLVs;
import pro.javacard.tlv.Tag;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.*;

// Security Domain applet implementing the GP card manager command set
public class SecurityDomainApplet extends Applet {

    private static final Logger log = LoggerFactory.getLogger(SecurityDomainApplet.class);

    // Default ISD privilege profile (GPC v2.3.1 6.6.1 Table 6-1 / 6.6.2), used by the engine bootstrap when creating the ISD entry.
    public static final EnumSet<Privilege> ISD_DEFAULT_PRIVILEGES = EnumSet.of(Privilege.SecurityDomain, Privilege.AuthorizedManagement, Privilege.GlobalRegistry, Privilege.GlobalLock, Privilege.GlobalDelete, Privilege.TokenVerification, Privilege.CardLock, Privilege.CardTerminate, Privilege.TrustedPath, Privilege.CVMManagement, Privilege.CardReset, Privilege.FinalApplication, Privilege.ReceiptGeneration);
    public static final byte FACTORY_KVN = (byte) 0xFF;
    final boolean isd;

    // SSD creation
    public SecurityDomainApplet() {
        isd = false;
    }

    // ISD bootstrap
    public SecurityDomainApplet(KeySet master) {
        isd = true;
        keys.put(master.kvn(), master);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // SSD must hold SecurityDomain + TrustedPath.
        short privOff = (short) (bOffset + 1 + bArray[bOffset]);
        byte privLen = bArray[privOff];
        var privs = EngineRegistryEntry.decodePrivileges(Arrays.copyOfRange(bArray, privOff + 1, privOff + 1 + privLen));
        if (!privs.contains(Privilege.SecurityDomain) || !privs.contains(Privilege.TrustedPath)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        new SecurityDomainApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public static final AID OPEN_AID = AIDUtil.create("A000000151000000");

    // Default SSD package + module AIDs
    public static final AID SSD_PACKAGE_AID = AIDUtil.create("A0000001515350");
    public static final AID SSD_MODULE_AID = AIDUtil.create("A000000151535041");

    static final byte[] DEFAULT_CPLC = Hex.decode("4242000000000000000042424A43454E4242000000000000000000000000000000000000000000000000");

    private static final byte INS_SELECT = (byte) 0xA4;
    private static final byte INS_GET_DATA = (byte) 0xCA;
    private static final byte INS_PUT_KEY = (byte) 0xD8;
    private static final byte INS_STORE_DATA = (byte) 0xE2;
    private static final byte INS_DELETE = (byte) 0xE4;
    private static final byte INS_INSTALL = (byte) 0xE6;
    private static final byte INS_LOAD = (byte) 0xE8;
    private static final byte INS_SET_STATUS = (byte) 0xF0;
    private static final byte INS_GET_STATUS = (byte) 0xF2;

    // Tag values from GPC v2.3.1, GPC v2.3.1 Amd C and ISO 7816-4. Hex suffix matches spec tables.
    private static final int TAG_AID_4F = 0x4F;
    private static final int TAG_FCI_6F = 0x6F;
    private static final int TAG_CL_STATE_81 = 0x81;
    private static final int TAG_DF_NAME_84 = 0x84;
    private static final int TAG_CL_STATE_TEMPLATE_A0 = 0xA0;
    // GPC v2.3.1 Amd C 11.2.3 Table 11-5: "User Interaction Parameters" template inside EF.
    private static final int TAG_USER_INTERACTION_PARAMETERS_A1 = 0xA1;
    private static final int TAG_CREL_ADD_A3 = 0xA3;
    private static final int TAG_CREL_REMOVE_A4 = 0xA4;
    private static final int TAG_FCI_PROPRIETARY_A5 = 0xA5;
    private static final int TAG_LOAD_FILE_AID_C4 = 0xC4;
    private static final int TAG_PRIVILEGES_C5 = 0xC5;
    private static final int TAG_APPLICATION_PARAMETERS_C9 = 0xC9;
    private static final int TAG_ASSOCIATED_SD_AID_CC = 0xCC;
    private static final int TAG_KEY_IDENTIFIER_D0 = 0xD0;
    private static final int TAG_KEY_VERSION_NUMBER_D2 = 0xD2;
    private static final int TAG_REGISTRY_DATA_E3 = 0xE3;
    private static final int TAG_SYSTEM_SPECIFIC_PARAMETERS_EF = 0xEF;
    private static final int TAG_LIFECYCLE_STATE_9F70 = 0x9F70;

    // SW values not present in this project's javacard.framework.ISO7816.
    private static final short SW_REFERENCED_DATA_NOT_FOUND = 0x6A88;
    private static final short SW_RESPONSE_BYTES_REMAINING = 0x6310;
    private static final short SW_FUNC_NOT_SUPPORTED = 0x6A81;
    // GPC v2.3.1 Table 11-83: SELECT of a Final Application SD while card is CARD_LOCKED
    private static final short SW_CARD_LOCKED = 0x6283;

    // INSTALL P1 function bits (GPC v2.3.1 Table 11-41); b8 = "more INSTALL commands following" masked off.
    // The install (b3) and make selectable (b4) bits combine: 0x04 install-only, 0x08 make selectable,
    // 0x0C install and make selectable.
    private static final byte P1_BIT_LOAD = (byte) 0x02;
    private static final byte P1_BIT_INSTALL = (byte) 0x04;
    private static final byte P1_BIT_MAKE_SELECTABLE = (byte) 0x08;
    private static final byte P1_INSTALL_FOR_EXTRADITION = (byte) 0x10;
    private static final byte P1_INSTALL_FOR_PERSONALIZATION = (byte) 0x20;
    private static final byte P1_INSTALL_FOR_REGISTRY_UPDATE = (byte) 0x40;

    // GET STATUS chunked-response state.
    private byte[] pendingStatus;
    private short pendingStatusOffset;
    private byte pendingStatusP1;

    // STORE DATA target set by INSTALL [for Personalization]
    private AID personalizationTarget;

    // Multi-block STORE DATA accumulator for the GP-data path.
    private ByteArrayOutputStream storeDataBuffer;

    // Keys owned by this Security Domain.
    private final LinkedHashMap<Byte, KeySet> keys = new LinkedHashMap<>();

    // Minimal SD SELECT response (GPC v2.3.1 11.9.3.1): 6F { 84 <aid> | A5 { 9F65 01 FF } }
    static byte[] fci(AID aid) {
        return TLV.build(TAG_FCI_6F).add(TAG_DF_NAME_84, AIDUtil.bytes(aid)).add(TLV.build(TAG_FCI_PROPRIETARY_A5).add(GPData.MAX_COMMAND_DATA_LENGTH.tag(), new byte[]{(byte) 0xFF})).encode();
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        var sim = Simulator.current();
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        var sc = sim.gp().getSecureChannel();

        // Any APDU that is not a GET STATUS continuation invalidates the pending response.
        if (ins != INS_GET_STATUS || (buffer[ISO7816.OFFSET_P2] & 0x01) == 0) {
            pendingStatus = null;
        }

        // Any APDU that is not a STORE DATA invalidates a pending personalization sequence
        if (ins != INS_STORE_DATA) {
            personalizationTarget = null;
            storeDataBuffer = null;
        }

        if (selectingApplet()) {
            byte[] fci = fci(JCSystem.getAID());
            Util.arrayCopyNonAtomic(fci, (short) 0, buffer, (short) 0, (short) fci.length);
            apdu.setOutgoingAndSend((short) 0, (short) fci.length);
            // GPC v2.3.1 Table 11-83: warning 6283 (FCI still returned) when selecting a Final Application while CARD_LOCKED.
            var self = sim.gp().getRegistryEntry(null);
            if (self.isPrivileged(GPRegistryEntry.PRIVILEGE_FINAL_APPLICATION) && sim.gp().getCardState() == GPSystem.CARD_LOCKED) {
                ISOException.throwIt(SW_CARD_LOCKED);
            }
            return;
        }

        // A SELECT [by name] reaching the ISD while it is already selected is an OPEN miss dispatched to
        // the current Application (GPC v2.3.1 6.4.2.1.2): answer application not found.
        if (ins == INS_SELECT) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        if (ins == EngineSecureChannel.INS_INITIALIZE_UPDATE || ins == EngineSecureChannel.INS_EXTERNAL_AUTHENTICATE) {
            // INITIALIZE UPDATE resolves its own master keys (caller context + KVN) inside the secure
            // channel; EXTERNAL AUTHENTICATE reuses the session it established.
            short len = sc.processSecurity(apdu);
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
            return;
        }

        // GET DATA runs unauthenticated (CPLC/KIT are public; GPC v2.3.1 11.3 does not mandate
        // auth): dispatched before the auth gate, no unwrap(), so clients send it plain.
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

        // Funnel malformed-data IllegalArgumentException (AIDUtil.create, LV.parse) to SW_WRONG_DATA.
        try {
            switch (ins) {
                case INS_INSTALL -> handleInstall(apdu, buffer, payload);
                case INS_STORE_DATA -> handleStoreData(apdu, buffer, payload);
                case INS_DELETE -> handleDelete(apdu, buffer, payload);
                case INS_PUT_KEY -> handlePutKey(apdu, buffer, payload);
                case INS_SET_STATUS -> handleSetStatus(apdu, buffer, payload);
                case INS_GET_STATUS -> handleGetStatus(apdu, buffer);
                case INS_LOAD -> ISOException.throwIt(SW_FUNC_NOT_SUPPORTED);
                default -> ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (IllegalArgumentException e) {
            log.warn("Malformed APDU data: {}", e.getMessage());
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }

    // Keys are this SD's own, else its parent SD's - never deeper. A sub-SSD cannot be created until
    // its owning SSD is personalized (owns keys), so a two-level check covers every real hierarchy.
    static Optional<KeySet> resolveKeySet(EngineRegistryEntry self, byte requestedKvn) {
        var own = selectKeySet(self, requestedKvn);
        return own.isPresent() ? own : selectKeySet(self.getParentSD(), requestedKvn);
    }

    // Pick a key set from one SD: requestedKvn 0 = newest, else the exact KVN. Empty if sd holds none.
    private static Optional<KeySet> selectKeySet(EngineRegistryEntry sd, byte requestedKvn) {
        if (!(sd.getApplet() instanceof SecurityDomainApplet sda) || sda.keys.isEmpty()) {
            return Optional.empty();
        }
        if (requestedKvn == 0) {
            return sda.keys.values().stream().reduce((a, b) -> b);
        }
        return Optional.ofNullable(sda.keys.get(requestedKvn));
    }

    private static final int INSTALL_LV_FIELD_COUNT = 6;

    // Opaque INSTALL EF System Specific Parameters stored raw on the entry (GPC v2.3.1 Table 11-49);
    // CB is handled separately (drives service registration), A0/A1 above carry CL semantics.
    private static final List<GPTag> EF_SYSTEM_PARAMS = List.of(GPData.VOLATILE_MEMORY_QUOTA, GPData.NON_VOLATILE_MEMORY_QUOTA, GPData.VOLATILE_RESERVED_MEMORY, GPData.NON_VOLATILE_RESERVED_MEMORY, GPData.TS_102_226_PARAMETER, GPData.IMPLICIT_SELECTION_PARAMETER);

    private void handleInstall(APDU apdu, byte[] buffer, byte[] payload) {
        byte p1 = (byte) (buffer[ISO7816.OFFSET_P1] & 0x7F);

        if ((p1 & P1_BIT_LOAD) != 0) {
            log.warn("INSTALL [for load] not supported");
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED);
        }

        var fields = LV.parse(payload);
        LV.visualize(payload).forEach(log::info);

        if (fields.size() != INSTALL_LV_FIELD_COUNT) {
            throw new IllegalArgumentException("INSTALL: expected " + INSTALL_LV_FIELD_COUNT + " LV fields, got " + fields.size());
        }

        switch (p1) {
            case P1_INSTALL_FOR_PERSONALIZATION -> installForPersonalization(apdu, buffer, fields);
            case P1_INSTALL_FOR_EXTRADITION -> installForExtradition(apdu, buffer, fields);
            case P1_INSTALL_FOR_REGISTRY_UPDATE -> installForRegistryUpdate(apdu, buffer, fields);
            default -> {
                boolean makeSelectable = (p1 & P1_BIT_MAKE_SELECTABLE) != 0;
                if ((p1 & P1_BIT_INSTALL) != 0) {
                    installForInstallAndMakeSelectable(apdu, buffer, fields, makeSelectable);
                } else if (makeSelectable) {
                    installForMakeSelectable(apdu, buffer, fields);
                } else {
                    log.warn("INSTALL: unsupported P1=0x%02X".formatted(buffer[ISO7816.OFFSET_P1] & 0xFF));
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                }
            }
        }
    }

    // GPC v2.3.1 7.3.2 / 9.3.x: OPEN refuses Card Content management while the card is LOCKED or TERMINATED.
    private static void checkCardNotLocked() {
        byte cardState = Simulator.current().gp().getCardState();
        if (cardState == GPSystem.CARD_LOCKED || cardState == GPSystem.CARD_TERMINATED) {
            log.warn("Card content management refused, card LOCKED or TERMINATED: 0x{}", String.format("%02X", cardState & 0xFF));
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    // GPC v2.3.1 9.3.6 / 9.3.7: the installing SD must hold Authorized Management and, unless it is the
    // ISD, be in the PERSONALIZED state before it may install or make an Application selectable.
    private static void checkInstallerAuthorized(EngineRegistryEntry self) {
        if (!self.getPrivileges().contains(Privilege.AuthorizedManagement)) {
            log.warn("Card content management refused, SD lacks Authorized Management: {}", self.getAID());
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (self.getKind() != Kind.ISD && self.getState() != GPSystem.SECURITY_DOMAIN_PERSONALIZED) {
            log.warn("Card content management refused, non-ISD SD not PERSONALIZED: {}", self.getAID());
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    private static EngineRegistryEntry isd() {
        return Simulator.current().gp().isd();
    }

    // INSTALL [for Personalization] - sets the STORE DATA target on the OPEN.
    // Field layout (GPC v2.3.1 11.5.2.3.6, Table 11-47): empty | empty | Application AID | empty | empty | empty.
    private void installForPersonalization(APDU apdu, byte[] buffer, List<byte[]> fields) {
        // GPC v2.3.1 7.3.2: the OPEN forwards perso commands only when the card is not LOCKED/TERMINATED.
        // A later lock is moot - SET STATUS is not a STORE DATA, so it already nulls personalizationTarget.
        checkCardNotLocked();
        var targetAid = AIDUtil.create(fields.get(2));
        var instance = Simulator.current().gp().lookup(targetAid);
        if (instance == null) {
            log.warn("Personalization target applet not found: {}", targetAid);
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        Applet target = instance.getApplet();
        if (!(target instanceof Personalization) && !(target instanceof Application)) {
            log.warn("Perso target lacks Personalization/Application: {}", targetAid);
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // GPC v2.3.1 6.7: the Trusted Framework forwards only when the Receiving Entity (this SD)
        // holds Trusted Path and the target is associated with it.
        var self = Simulator.current().gp().getRegistryEntry(null);
        if (!self.getPrivileges().contains(Privilege.TrustedPath)) {
            log.warn("INSTALL [for personalization]: receiving SD lacks Trusted Path: {}", self.getAID());
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        var targetSD = instance.getParentSD();
        if (!targetSD.getAID().equals(self.getAID())) {
            log.warn("INSTALL [for personalization]: target not associated with receiving SD: {}", targetAid);
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        personalizationTarget = targetAid;
        buffer[0] = 0x00;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    // INSTALL [for Install (and Make Selectable)] - instantiates an applet from a loaded package.
    // makeSelectable=false (P1 b3 only) leaves the new instance INSTALLED; true (b3|b4) makes it SELECTABLE.
    // Field layout (GPC v2.3.1 11.5.2.3.2, Table 11-43): ELF AID | Module AID | App AID | Privileges | Install Params | Token.
    private void installForInstallAndMakeSelectable(APDU apdu, byte[] buffer, List<byte[]> fields, boolean makeSelectable) {
        var sim = Simulator.current();
        var self = sim.gp().getRegistryEntry(null);
        checkCardNotLocked();
        checkInstallerAuthorized(self);

        var pkg = AIDUtil.create(fields.get(0));
        var app = AIDUtil.create(fields.get(1));
        var instanceAid = AIDUtil.create(fields.get(2));
        var privileges = fields.get(3);
        // Full install-parameters block; the applet's install() only sees the C9-inner slice below.
        var installParams = fields.get(4);
        var appletClass = sim.gp().locateApplet(pkg, app);

        if (appletClass == null) {
            log.warn("Applet not found");
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        boolean isSD = appletClass == SecurityDomainApplet.class;
        var decodedPrivileges = EngineRegistryEntry.decodePrivileges(privileges);

        // Duplicate instance AID can never register() - it throws SystemException.ILLEGAL_AID,
        // swallowed into JavaCardEngineException downstream. Reject every duplicate here at the
        // parameter stage with the spec-mandated 0x6985, before any registry mutation.
        if (sim.gp().lookup(instanceAid) != null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // GPC v2.3.1 Table 11-43: Card Reset cannot be set when installing without making selectable.
        if (!makeSelectable && decodedPrivileges.contains(Privilege.CardReset)) {
            log.warn("CardReset privilege requires make-selectable in same INSTALL");
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Top level: C9 (applet payload) + optional EF (contactless install hints). All EF
        // validation runs before internalInstallApplet so a bad block aborts with no partial
        // mutation - post-commit events cannot be unfired.
        byte[] appletParams = new byte[0];
        TLVs top;
        Optional<CLState> clState;
        try {
            top = TLV.parse(installParams);
            appletParams = top.find(TAG_APPLICATION_PARAMETERS_C9).map(TLV::value).orElse(appletParams);
            clState = clStateOf(top); // validate the CL-state byte before commit (rollback test relies on this)
        } catch (IllegalArgumentException e) {
            log.warn("INSTALL [install]: malformed install parameters: {}", e.getMessage());
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return; // unreachable; throwIt always throws
        }

        var pkgEntry = sim.gp().lookup(pkg);
        if (pkgEntry == null) {
            ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
        }
        // exposed=true for the SD class: platform code touching Simulator/GP statics, not isolated.
        sim.internalInstallApplet(instanceAid, appletClass, privileges, appletParams, isSD, pkgEntry);

        // Commit done; apply CL params and fan out EVENT_SELECTABLE. Straight-line, no rollback -
        // everything fed below was validated above.
        var newEntry = sim.gp().lookup(instanceAid);
        if (newEntry != null && newEntry.getKind() != Kind.PKG) {
            applyEF(newEntry, top);
            // GPC v2.3.1 Amd C 8.3: EVENT_SELECTABLE and the initial CL activation state apply when the
            // Application is made selectable - here for install & make selectable, or later via a standalone
            // INSTALL [for make selectable]. Install-only (b3 without b4) stays INSTALLED and fires nothing.
            if (makeSelectable) {
                clState.ifPresent(s -> newEntry.initial = s);
                ContactlessEngine.notifyContactlessEvent(newEntry, CLAppletEvent.EVENT_SELECTABLE);
                // GPC v2.3.1 Amd C 8.3: first make-selectable attempts the Initial Contactless Activation State.
                // TODO: GPC v2.3.1 Amd C 8.3 / Table 11-7 - warning 6200 when activation cannot be honored.
                ContactlessEngine.applyInitial(newEntry);
            } else {
                newEntry.internalForceState(GPSystem.APPLICATION_INSTALLED);
            }
        }

        // The update counter is bumped by gp().register() at the commit point (GPC v2.3.1 Amd C 3.11.2.3).
        buffer[0] = 0x00;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    // INSTALL [for make selectable] - promote a previously installed Application to SELECTABLE (GPC v2.3.1 9.3.7).
    // Field layout (GPC v2.3.1 11.5.2.3.3, Table 11-44): empty | empty | App AID | Privileges | Make Selectable Params | Token.
    private void installForMakeSelectable(APDU apdu, byte[] buffer, List<byte[]> fields) {
        var sim = Simulator.current();
        var self = sim.gp().getRegistryEntry(null);
        checkCardNotLocked();
        checkInstallerAuthorized(self);

        // GPC v2.3.1 9.3.7: the Application AID must be present in the registry.
        var appAid = AIDUtil.create(fields.get(2));
        var entry = sim.gp().lookup(appAid);
        if (entry == null || entry.getKind() == Kind.PKG) {
            log.warn("INSTALL [for make selectable]: application not in registry: {}", appAid);
            ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
        }
        // internalForceState bypasses the GP-API setState gate, which deliberately rejects INSTALLED ->
        // SELECTABLE so the promotion happens only through this command (GPC v2.3.1 5.3.1.2).
        entry.internalForceState(GPSystem.APPLICATION_SELECTABLE);
        // GPC v2.3.1 Amd C 8.3: EVENT_SELECTABLE fires when the Application is made selectable, and the
        // OPEN attempts the Initial Contactless Activation State on this first transition to SELECTABLE.
        ContactlessEngine.notifyContactlessEvent(entry, CLAppletEvent.EVENT_SELECTABLE);
        ContactlessEngine.applyInitial(entry);
        // Privileges (field 3) / Make Selectable Params (field 4) registry update and Token (field 5)
        // verification are out of scope (see installForInstallAndMakeSelectable TODO).
        buffer[0] = 0x00;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    // INSTALL [for registry update] - update a live Application's contactless / system registry
    // parameters in place (GPC v2.3.1 11.5.2.3.5; Amd C 11.2). Field layout mirrors install:
    // SD AID | (empty) | App AID | Privileges | Registry Update Params | Token. Only the App AID and
    // the params are consumed; privilege change, SD re-association and token verification are out of scope.
    private void installForRegistryUpdate(APDU apdu, byte[] buffer, List<byte[]> fields) {
        var sim = Simulator.current();
        var self = sim.gp().getRegistryEntry(null);
        checkCardNotLocked();
        checkInstallerAuthorized(self);

        byte[] aidField = fields.get(2);
        TLVs top;
        Optional<CLState> clState;
        try {
            top = TLV.parse(fields.get(4));
            clState = clStateOf(top); // validate the CL-state byte before any mutation
        } catch (IllegalArgumentException e) {
            log.warn("INSTALL [for registry update]: malformed parameters: {}", e.getMessage());
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return; // unreachable; throwIt always throws
        }

        // GPC v2.3.1 Amd C 8.3 / 4.2: an empty AID field updates the OPEN-owned default Initial Contactless
        // Activation State, modifiable only by the Issuer Security Domain. Other OPEN params are out of scope.
        if (aidField.length == 0) {
            if (self != isd()) {
                log.warn("INSTALL [for registry update]: OPEN default update requires the ISD: {}", self.getAID());
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            clState.ifPresent(s -> sim.gp().defaultInitial = s);
            buffer[0] = 0x00;
            apdu.setOutgoingAndSend((short) 0, (short) 1);
            return;
        }

        // GPC v2.3.1 9.4.2.1: the Application being updated must exist in the registry.
        var appAid = AIDUtil.create(aidField);
        var entry = sim.gp().lookup(appAid);
        if (entry == null || entry.getKind() == Kind.PKG) {
            log.warn("INSTALL [for registry update]: application not in registry: {}", appAid);
            ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
        }
        // GPC v2.3.1 9.4.2.1: only the target's associated SD may update its registry; a cross-SD update
        // needs Global Registry (consent of the associated SD is not modelled). Same gate as SET STATUS.
        if (!entry.getParentSD().getAID().equals(self.getAID()) && !self.isPrivileged(GPRegistryEntry.PRIVILEGE_GLOBAL_REGISTRY)) {
            log.warn("INSTALL [for registry update]: {} not associated with caller {}", appAid, self.getAID());
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        applyEF(entry, top);
        // GPC v2.3.1 Amd C 8.3 / Table 11-3: tag 81 updates the stored Initial Contactless Activation State.
        // The current activation state is untouched (that is SET STATUS / CRS), so no event and no counter bump.
        clState.ifPresent(s -> entry.initial = s);
        buffer[0] = 0x00;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    // CL activation state from EF { A0 { 81 } }, if present. Throws on a bad state byte (CLState.parse)
    // so callers can validate before the commit / first event fires.
    private static Optional<CLState> clStateOf(TLVs top) {
        return top.find(TAG_SYSTEM_SPECIFIC_PARAMETERS_EF, TAG_CL_STATE_TEMPLATE_A0, TAG_CL_STATE_81)
                .map(c -> CLState.parse(c.value()));
    }

    // Apply EF { A1 (Table 11-5): A3/A4 = CREL add/remove, 87/88/... = Application Info slots ;
    // CB = Global Service Parameters ; opaque system params } to a registry entry in place (GPC v2.3.1
    // Amd C 11.2). Per 11.2.3 setInfoInternal deletes on zero-length / replaces otherwise; A3/A4 are
    // additive / subtractive (setInfoInternal bypasses the GP-API caller gate: the SD is the OPEN-side
    // actor). CL state (tag 81) is caller-applied; see clStateOf(). Shared by install and registry update.
    private static void applyEF(EngineRegistryEntry entry, TLVs top) {
        for (var aid : crelAids(top, TAG_CREL_ADD_A3)) {
            entry.addToCRELApplicationList(aid, (short) 0, (short) aid.length);
        }
        for (var aid : crelAids(top, TAG_CREL_REMOVE_A4)) {
            entry.removeFromCRELApplicationList(aid, (short) 0, (short) aid.length);
        }
        var ef = top.find(TAG_SYSTEM_SPECIFIC_PARAMETERS_EF);
        var a1 = ef.flatMap(e -> e.find(TAG_USER_INTERACTION_PARAMETERS_A1));
        a1.ifPresent(a -> {
            for (var element : GPData.installInfos()) {
                a.find(element.tag()).ifPresent(sub -> {
                    var v = sub.value();
                    entry.setInfoInternal(v, (short) 0, (short) v.length, element);
                });
            }
        });
        ef.flatMap(e -> e.find(GPData.GLOBAL_SERVICE_PARAMETERS.tag())).ifPresent(cb -> {
            for (var name : parseServiceNames(cb.value())) {
                entry.recordInstalledService(name);
            }
        });
        for (var element : EF_SYSTEM_PARAMS) {
            ef.flatMap(e -> e.find(element.tag())).ifPresent(sub -> entry.putSystemParam(element, sub.value()));
        }
    }

    // INSTALL [for extradition] - rebind an APP/SSD/PKG to a new associated SD (GPC v2.3.1 11.5.2.3.4).
    // Field layout: new SD AID | empty | App or ELF AID | empty | empty | token.
    // Caller must hold AM or DM (GPC v2.3.1 9.4.1); ISD has AM by default.
    private void installForExtradition(APDU apdu, byte[] buffer, List<byte[]> fields) {
        var sim = Simulator.current();
        var caller = sim.caller();
        if (caller == null || (!caller.isPrivileged(GPRegistryEntry.PRIVILEGE_AUTHORIZED_MANAGEMENT) && !caller.isPrivileged(GPRegistryEntry.PRIVILEGE_DELEGATED_MANAGEMENT))) {
            log.warn("INSTALL [for extradition]: caller lacks AM/DM privilege: {}", caller == null ? null : caller.getAID());
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        var newSD = AIDUtil.create(fields.get(0));
        var target = AIDUtil.create(fields.get(2));

        // Pre-validate to map each failure mode to a GP-correct SW.
        if (target.equals(newSD)) {
            log.warn("INSTALL [for extradition]: self-extradition rejected: {}", target);
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        var newSDEntry = sim.gp().lookup(newSD);
        if (newSDEntry == null || (newSDEntry.getKind() != Kind.ISD && newSDEntry.getKind() != Kind.SSD)) {
            log.warn("INSTALL [for extradition]: new SD not found or not an SD: {}", newSD);
            ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
        }
        var targetEntry = sim.gp().lookup(target);
        if (targetEntry == null) {
            log.warn("INSTALL [for extradition]: target not found: {}", target);
            ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
        }
        if (targetEntry.getKind() == Kind.ISD) {
            log.warn("INSTALL [for extradition]: ISD cannot be extradited");
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Rebind: key-resolution chain-walks now reach the new SD. Engine mutates and bumps the counter.
        sim.gp().extradite(targetEntry, newSDEntry);
        log.info("Extradited {} to SD {}", target, newSD);
        buffer[0] = 0x00;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    // STORE DATA - two roles, split on whether a personalization target is set:
    //   1) target set -> forward payload to that Application/Personalization (GPC v2.3.1 7.3.2).
    //   2) no target  -> BER-TLV GP data write (GPC v2.3.1 11.11), handled by handleStoreGPData.
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
        log.warn("STORE DATA: target lacks Personalization/Application: {}", targetAid);
        personalizationTarget = null;
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Accumulate across blocks, parse BER-TLV on the last. P1 format bits 0x18: 00 and 10 share
    // the same wire form here; 11 (encrypted) is rejected.
    private void handleStoreGPData(APDU apdu, byte[] buffer, byte[] payload) {
        byte p1 = buffer[ISO7816.OFFSET_P1];
        int format = p1 & 0x18;
        if (format == 0x18) {
            log.warn("STORE DATA: encrypted format unsupported (P1=0x{})", String.format("%02X", p1 & 0xFF));
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
        var self = Simulator.current().gp().getRegistryEntry(null);
        for (TLV tlv : TLV.parse(all)) {
            byte[] value = tlv.value();
            var element = GPData.byTag(tagToInt(tlv.tag())).orElse(null);
            if (element == GPData.CPLC_PERSO_SLICE) {
                writeCPLCSlice(self, 34, value);
            } else if (element == GPData.CPLC_PREPERSO_SLICE) {
                writeCPLCSlice(self, 26, value);
            } else if (element == GPData.CPLC) {                 // full CPLC overwrite is not allowed
                log.warn("STORE DATA: CPLC (9F7F) is read-only");
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            } else if (element == GPData.AID) {                  // tag 4F renames the ISD (GPC v2.3.1 11.11.2.3)
                if (self.getKind() != Kind.ISD) {                // 4F is settable only on the Issuer SD, not an SSD
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                // AIDUtil.create rejects length outside 5..16, renameISD rejects a collision: both -> 6A80.
                Simulator.current().gp().renameISD(AIDUtil.create(value));
            } else if (element == null) {                        // only GPData-defined data objects are stored
                log.warn("STORE DATA: unknown data object {}", tlv.tag().toHex());
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            } else {
                self.putData(element, value);
            }
        }
    }

    // Splice an 8-byte slice into the SD's CPLC (read-modify-write on the 9F7F data object). Only the
    // ISD holds CPLC, so a slice write to any other SD is rejected (getData returns null).
    private static void writeCPLCSlice(EngineRegistryEntry self, int offset, byte[] value) {
        byte[] cplc = self.getData(GPData.CPLC);
        if (cplc == null || value == null || value.length != 8) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        Util.arrayCopyNonAtomic(value, (short) 0, cplc, (short) offset, (short) 8);
        self.putData(GPData.CPLC, cplc);
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
    // data field - there is no P1/P2 flag distinguishing them:
    //   '4F'        -> DELETE [card content] (Table 11-23) - applet/load file by AID.
    //   'D0' / 'D2' -> DELETE [key] (Table 11-24) - keyset by Key Identifier / Key Version Number.
    private void handleDelete(APDU apdu, byte[] buffer, byte[] payload) {
        var tlvs = TLV.parse(payload);

        // GPC v2.3.1 Tables 11-23 / 11-24: top-level tag layouts for DELETE [card content]
        // vs DELETE [key].
        var d0 = TLV.find(tlvs, TAG_KEY_IDENTIFIER_D0).orElse(null);
        var d2 = TLV.find(tlvs, TAG_KEY_VERSION_NUMBER_D2).orElse(null);
        if (d0 != null || d2 != null) {
            handleDeleteKey(apdu, buffer, d0, d2);
            return;
        }

        // DELETE [card content] (Table 11-23): '4F' Lc AID [further CRT tags...].
        var aidTlv = TLV.find(tlvs, TAG_AID_4F);
        if (aidTlv.isEmpty()) {
            log.warn("DELETE: missing 4F AID tag");
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }
        var aid = AIDUtil.create(aidTlv.get().value());

        // GPC v2.3.1 Amd C deletion: commit first (uninstall + registry removal), then fan out
        // EVENT_DELETED - mirror of INSTALL. We hold `target` so the CL entry outlives removal.
        var sim = Simulator.current();
        var target = sim.gp().lookup(aid);
        if (target == null) {
            log.warn("DELETE: applet {} not registered", aid);
            ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
            return; // unreachable, keeps the compiler happy
        }
        if (target.getKind() == Kind.ISD) {
            log.warn("DELETE: ISD cannot be deleted");
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // markDisabled() tombstones the entry: every method but getAID() then throws ILLEGAL_USE.
        // CREL fan-out reads via internalGetCRELs which bypasses the gate.
        sim.internalDeleteApplet(aid);
        target.markDisabled();

        // Self-delivery is suppressed in notifyContactlessEvent (Amd C 3.10.4). CREL lists on
        // other applications referencing this AID are NOT pruned (3.8.2: metadata outlives install).
        // PKG entries have no CL surface, so skip the round-trip.
        if (target.getKind() != Kind.PKG) {
            ContactlessEngine.notifyContactlessEvent(target, CLAppletEvent.EVENT_DELETED);
        }

        // The update counter is bumped by internalDeleteApplet -> gp().remove() above (GPC v2.3.1 Amd C 3.11.2.3).
        buffer[0] = 0x00;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    // DELETE [key] (GPC v2.3.1 11.2.2.3.2). KeySet stores an ENC/MAC/DEK triple atomically per KVN,
    // so only the "D2 only -> drop the whole KVN" form is supported; any D0 (per-KID) is rejected.
    private void handleDeleteKey(APDU apdu, byte[] buffer, TLV d0, TLV d2) {
        if (d0 != null) {
            log.warn("DELETE [key]: D0 (per-KID) unsupported; grain is per-KVN");
            ISOException.throwIt(SW_FUNC_NOT_SUPPORTED);
        }
        if (d2.value().length != 1) {
            log.warn("DELETE [key]: 'D2' tag must be 1 byte, got {}", d2.value().length);
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        byte kvn = d2.value()[0];

        if (keys.remove(kvn) == null) {
            log.warn("DELETE [key]: no keyset for KVN=0x{}", String.format("%02X", kvn & 0xFF));
            ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
        }

        buffer[0] = 0x00;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    // PUT KEY (GPC v2.3.1 11.8). P1 = 0 adds a new KVN, else replaces that KVN. P2 = first KID
    // | 0x80 (multi-key flag); gp-pro sends 0x81 + ENC/MAC/DEK in one APDU.
    // Body: new_KVN | block_ENC | block_MAC | block_DEK, each block:
    //   AES  88 | block_len | actual_key_len | cgram | kcv_len | kcv
    //   DES3 80 | block_len | cgram | kcv_len | kcv
    // Response: new_KVN | KCV_KID1 | KCV_KID2 | KCV_KID3 (3 bytes each).
    private void handlePutKey(APDU apdu, byte[] buffer, byte[] payload) {
        var sim = Simulator.current();
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

        byte newKvn = bb.get();
        int kvnUnsigned = newKvn & 0xFF;
        if (kvnUnsigned < 0x01 || kvnUnsigned > 0x7F) {
            log.warn("PUT KEY: KVN out of range 0x01..0x7F: 0x{}", String.format("%02X", kvnUnsigned));
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        var sd = sim.gp().getRegistryEntry(null);

        if (p1 == 0) {
            if (keys.get(newKvn) != null) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        } else {
            if (p1 != newKvn) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            if (keys.get(p1) == null) {
                ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
            }
        }

        var sc = sim.gp().getSecureChannel();
        var entries = new TreeMap<Byte, KeySet.KeyEntry>();
        var kcvOut = new ByteArrayOutputStream();
        kcvOut.write(newKvn & 0xFF);

        for (byte kid = KeySet.KID_ENC; kid <= KeySet.KID_DEK; kid++) {
            entries.put(kid, parseKeyBlock(bb, sc, payload, kcvOut));
        }
        if (bb.hasRemaining()) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        if (keys.size() == 1) {
            keys.remove(FACTORY_KVN);
        }
        // Remove first so a re-put moves the KVN to newest (LinkedHashMap keeps insertion order).
        keys.remove(newKvn);
        keys.put(newKvn, new KeySet(newKvn, entries));

        // GPC v2.3.1 Table 11-5: an SSD becomes PERSONALIZED on its first PUT KEY (now owns keys).
        // ISD lifecycle is the card LCS instead, driven by SET STATUS.
        // TODO: DM, tokens etc.
        if (sd.getKind() == Kind.SSD && sd.getState() == GPSystem.APPLICATION_SELECTABLE) {
            sd.setState(GPSystem.SECURITY_DOMAIN_PERSONALIZED);
        }

        byte[] response = kcvOut.toByteArray();
        Util.arrayCopyNonAtomic(response, (short) 0, buffer, (short) 0, (short) response.length);
        apdu.setOutgoingAndSend((short) 0, (short) response.length);
    }

    // Parse one PUT KEY block: decrypt cgram in place (SC picks session/static DEK), verify the
    // on-wire KCV, append the 3-byte KCV to the response.
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
            // No KCV on the wire - emit zeros to keep the response shape stable.
            kcvOut.writeBytes(new byte[3]);
        }
        return new KeySet.KeyEntry(type, keyValue);
    }

    // SET STATUS (GPC v2.3.1 11.10, Table 11-86). P1=0x80 is the ISD/card lifecycle (P2 = new
    // state, no data); P1=0x40 is the Application/SSD lifecycle (data = target AID, P2 = new
    // state per Table 11-87). Any other P1 is unsupported.
    private void handleSetStatus(APDU apdu, byte[] buffer, byte[] payload) {
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];
        if (p1 == (byte) 0x80) {
            handleSetCardStatus(apdu, buffer, payload, p2);
        } else if (p1 == (byte) 0x40) {
            handleSetApplicationStatus(apdu, buffer, payload, p2);
        } else {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
    }

    private void handleSetCardStatus(APDU apdu, byte[] buffer, byte[] payload, byte p2) {
        if (payload.length != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        var sim = Simulator.current();
        boolean ok = sim.gp().setCardLifecycleState(p2);
        if (!ok) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // The update counter is bumped by gp().setCardLifecycleState() on success (GPC v2.3.1 Amd C 3.11.2.3).
        buffer[0] = 0x00;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    // SET STATUS [for application] (P1=0x40): the data field is the raw target Application AID,
    // P2 is the new life cycle state (b8 = LOCK per GPC v2.3.1 5.3.1). The associated SD may
    // lock/unlock its own applications; Global Lock permits locking/unlocking any application.
    private void handleSetApplicationStatus(APDU apdu, byte[] buffer, byte[] payload, byte p2) {
        var sim = Simulator.current();
        var target = sim.gp().lookup(AIDUtil.create(payload));
        if (target == null || target.getKind() == Kind.PKG) {
            ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
        }
        if (target.getKind() == Kind.ISD) {
            // The ISD card state is the P1=0x80 path; it is not an application target here.
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        // Reserved app LCS encodings (low byte 0x01/0x02, below INSTALLED) are not valid targets.
        if ((p2 & 0x7F) == 0x01 || (p2 & 0x7F) == 0x02) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        var caller = sim.gp().getRegistryEntry(null);
        boolean associated = target.getParentSD().getAID().equals(caller.getAID());
        if (!associated && !caller.isPrivileged(GPRegistryEntry.PRIVILEGE_GLOBAL_LOCK)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        // GPC v2.3.1 11.10.2.2: for another Application only b8 is relevant - an SD may LOCK or
        // UNLOCK it, never push an app-specific state. Keep the current low bits and flip only b8.
        byte locked = (byte) ((target.getState() & 0x7F) | (p2 & 0x80));
        if (locked == target.getState()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (!target.transition(locked, true, true)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        buffer[0] = 0x00;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    // GPC v2.3.1 11.4: tagged GET STATUS only (P2 bit 1 required). P1 = scope, P2 bit 0 =
    // continuation. Long responses chunked to the SC max payload; intermediate chunks return 0x6310.
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

        short chunk = Simulator.current().gp().getSecureChannel().maxResponseLength();
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

    // GPC v2.3.1 11.3: GET DATA returns the TLV item for tag P1P2 from the SD's data store. CPLC
    // (9F7F) is a usual tag there - card-wide, so it lives in the ISD's store. No chunking yet.
    private void handleGetData(APDU apdu, byte[] buffer) {
        int tag = Util.makeShort(buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]) & 0xFFFF;
        var element = GPData.byTag(tag).orElse(null);
        byte[] response;
        if (element == GPData.KEY_INFORMATION_TEMPLATE) {
            response = keyInformationTemplate();
        } else {
            var self = Simulator.current().gp().getRegistryEntry(null);
            byte[] stored = element == null ? null : self.getData(element);
            if (stored == null) {
                log.warn("GET DATA: unsupported tag 0x%04X".formatted(tag));
                ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
                return;
            }
            response = TLV.of(element.tag(), stored).encode();
        }
        Util.arrayCopyNonAtomic(response, (short) 0, buffer, (short) 0, (short) response.length);
        apdu.setOutgoingAndSend((short) 0, (short) response.length);
    }

    // GPC v2.3.1 11.3.3.1.1 (Table 11-28): 'E0' Key Information Template wrapping one C0 per (KID, KVN).
    private byte[] keyInformationTemplate() {
        var entries = keys.values().stream().flatMap(ks -> ks.keyInfoEntries().stream()).toList();
        return TLV.of(GPData.KEY_INFORMATION_TEMPLATE.tag(), entries).encode();
    }

    // Build the full GET STATUS response (concatenated E3 templates) for the given P1.
    private static byte[] buildStatusResponse(byte p1) {
        var sim = Simulator.current();
        var entries = new ArrayList<TLV>();

        switch (p1 & 0xFF) {
            case 0x80 -> sim.gp().getApplets().stream().filter(e -> e.getKind() == Kind.ISD).forEach(e -> entries.add(encodeAppletEntry(e)));
            case 0x40 ->
                    sim.gp().getApplets().stream().filter(e -> e.getKind() == Kind.APP || e.getKind() == Kind.SSD).forEach(e -> entries.add(encodeAppletEntry(e)));
            case 0x20 -> sim.gp().getPackages().forEach(e -> entries.add(encodePackageEntry(e, false)));
            case 0x10 -> sim.gp().getPackages().forEach(e -> entries.add(encodePackageEntry(e, true)));
            default -> ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        return TLV.encode(entries);
    }

    private static TLV encodeAppletEntry(EngineRegistryEntry e) {
        var tlv = TLV.build(TAG_REGISTRY_DATA_E3).add(TAG_AID_4F, AIDUtil.bytes(e.getAID())).add(TAG_LIFECYCLE_STATE_9F70, e.lifecycleState()).add(TAG_PRIVILEGES_C5, BitField.encode(e.getPrivileges(), 3));
        AID pkg = e.getPackageAID();
        if (pkg != null) {
            tlv.add(TAG_LOAD_FILE_AID_C4, AIDUtil.bytes(pkg));
        }
        tlv.add(TAG_ASSOCIATED_SD_AID_CC, AIDUtil.bytes(e.getParentSD().getAID()));
        return tlv;
    }

    private static TLV encodePackageEntry(EngineRegistryEntry e, boolean withModules) {
        var tlv = TLV.build(TAG_REGISTRY_DATA_E3).add(TAG_AID_4F, AIDUtil.bytes(e.getAID())).add(TAG_LIFECYCLE_STATE_9F70, e.lifecycleState());
        if (withModules) {
            for (var moduleAid : e.getModules().keySet()) {
                tlv.add(TAG_DF_NAME_84, AIDUtil.bytes(moduleAid));
            }
        }
        tlv.add(TAG_ASSOCIATED_SD_AID_CC, AIDUtil.bytes(e.getParentSD().getAID()));
        return tlv;
    }

    // GPC v2.3.1 8.1.3: CB value is one or more 2-byte service names (family, id). Each short = name.
    private static List<Short> parseServiceNames(byte[] value) {
        if (value.length == 0 || value.length % 2 != 0) {
            throw new IllegalArgumentException("CB Global Service Parameters must be a multiple of 2 bytes, got " + value.length);
        }
        var names = new ArrayList<Short>();
        for (int i = 0; i < value.length; i += 2) {
            names.add((short) (((value[i] & 0xFF) << 8) | (value[i + 1] & 0xFF)));
        }
        return names;
    }

    // GPC v2.3.1 Amd C Table 11-5: A3/A4 CREL lists carry a concatenation of 4F-tagged AID entries.
    // AID (4F) bytes listed in the EF/A1 CREL add/remove block (A3/A4); empty when the block is absent.
    private static List<byte[]> crelAids(TLVs top, int crelTag) {
        return top.findAll(TAG_SYSTEM_SPECIFIC_PARAMETERS_EF, TAG_USER_INTERACTION_PARAMETERS_A1, crelTag, TAG_AID_4F)
                .stream().map(TLV::value).toList();
    }
}
