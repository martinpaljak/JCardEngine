// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.*;
import org.globalplatform.GPRegistryEntry;
import org.globalplatform.contactless.CLAppletEvent;
import org.globalplatform.contactless.CRSApplication;
import org.globalplatform.contactless.GPCLRegistryEntry;
import org.globalplatform.contactless.GPCLSystem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.engine.globalplatform.GPNamedElement.GPInfo;
import pro.javacard.gp.GPRegistryEntry.Kind;
import pro.javacard.tlv.BERTag;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.Tag;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Default Contactless Registry Service applet (GPC v2.3.1 Amd C 3.11).
 * Instantiated at boot to {@code A00000015143525300}
 */
public final class EngineCRSApplet extends Applet implements CRSApplication {

    private static final Logger log = LoggerFactory.getLogger(EngineCRSApplet.class);

    // GPC v2.3.1 Amd C 3.11.1
    public static final AID CRS_AID = AIDUtil.create("A00000015143525300");
    static final AID CRS_PACKAGE_AID = AIDUtil.create("A000000151435253");

    // GPC v2.3.1 Amd C 3.11.3 / 3.11.4 / 3.11.6
    private static final byte INS_SET_STATUS = (byte) 0xF0;
    private static final byte INS_GET_STATUS = (byte) 0xF2;
    private static final byte INS_GET_DATA = (byte) 0xCA;

    // GPC v2.3.1 Amd C Table 3-32: GET DATA A5 proprietary template
    private static final byte P1_GET_DATA = (byte) 0x00;
    private static final byte P2_GET_DATA = (byte) 0xA5;

    // 0x84 = same with SCP indication, tolerated (SCP not enforced here)
    private static final byte CLA_GP = (byte) 0x80;
    private static final byte CLA_GP_SCP = (byte) 0x84;

    // SET STATUS P1=01 (Availability State); GET STATUS P1=40 (Applications scope)
    private static final byte P1_SET_AVAILABILITY = (byte) 0x01;
    private static final byte P1_GET_APPLICATIONS = (byte) 0x40;

    // BER tags in command/response data fields
    private static final int TAG_APPLICATION_TEMPLATE = 0x61;
    private static final int TAG_AID = 0x4F;
    private static final int TAG_FCI = 0x6F;
    private static final int TAG_FCI_AID = 0x84;
    private static final int TAG_FCI_PROPRIETARY = 0xA5;
    private static final int TAG_CRS_VERSION = 0x9F08;
    private static final int TAG_UPDATE_COUNTER = 0x80;
    private static final int TAG_LIFECYCLE = 0x9F70;
    private static final int TAG_FAILED_APPS = 0xA1;
    private static final int TAG_TAG_LIST = 0x5C;

    // Cached Tag instances for the frequently compared GET STATUS tags.
    private static final Tag T_AID = Tag.ber(TAG_AID);
    private static final Tag T_LIFECYCLE = Tag.ber(TAG_LIFECYCLE);
    private static final Tag T_TAG_LIST = Tag.ber(TAG_TAG_LIST);

    // GPC v2.3.1 Amd C 3.6: when display-required (88) was never installed, GET STATUS reports the
    // default "display not required". Synthesized here only; the GP-API getInfo() still reports unset.
    private static final byte[] DISPLAY_NOT_REQUIRED = new byte[]{0x00};

    // GPC v2.3.1 Amd C 3.11.5: CRS v1.0
    private static final byte[] CRS_VERSION_V1 = new byte[]{(byte) 0x01, (byte) 0x00};

    // SW values not present in this project's ISO7816
    private static final short SW_REFERENCED_DATA_NOT_FOUND = 0x6A88;
    private static final short SW_INCORRECT_VALUES = 0x6A80;
    private static final short SW_INCORRECT_P1P2_VARIANT = 0x6A86;
    private static final short SW_PARTIAL_FAILURE = 0x6320; // GPC v2.3.1 Amd C Table 3-28
    private static final short SW_MORE_DATA = 0x6310; // GPC v2.3.1 Amd C Table 3-16
    private static final short SW_FILE_FULL = 0x6A84; // SET STATUS A1 list overflow

    // GPC v2.3.1 Amd C Table 3-13: only bit 0 (continuation flag) defined, rest RFU
    private static final byte P2_CONTINUATION_FLAG = (byte) 0x01;
    private static final byte P2_RFU_MASK = (byte) 0xFE;

    // Short Le=00 caps payload at 256 (sim APDU buffer is 261)
    // TODO: we have a constant for this, returned in FCI and stored as a tag.
    private static final int CHUNK_SIZE = 256;

    // GET STATUS continuation cursor, CLEAR_ON_DESELECT so deselect/reset drops in-flight paging.
    // pagingBuffer[0] = encoded response (null when idle); pagingOffset[0] = next unsent index.
    private final Object[] pagingBuffer;
    private final short[] pagingOffset;

    public EngineCRSApplet() {
        pagingBuffer = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        pagingOffset = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
    }

    private byte[] paging() {
        return (byte[]) pagingBuffer[0];
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();

        if (selectingApplet()) {
            sendFci(apdu, buffer);
            return;
        }

        byte cla = buffer[ISO7816.OFFSET_CLA];
        if (cla != CLA_GP && cla != CLA_GP_SCP) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        byte ins = buffer[ISO7816.OFFSET_INS];
        switch (ins) {
            case INS_GET_STATUS -> handleGetStatus(apdu, buffer);
            case INS_SET_STATUS -> handleSetStatus(apdu, buffer);
            case INS_GET_DATA -> handleGetData(apdu, buffer);
            default -> ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // GPC v2.3.1 Amd C 3.11.6 / Tables 3-31 + 3-32: GET DATA returns the bare A5 template (9F08 + 80)
    private void handleGetData(APDU apdu, byte[] buffer) {
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];
        if (p1 != P1_GET_DATA || p2 != P2_GET_DATA) {
            ISOException.throwIt(SW_INCORRECT_P1P2_VARIANT);
        }
        byte[] response = buildProprietaryTemplate().encode();
        Util.arrayCopyNonAtomic(response, (short) 0, buffer, (short) 0, (short) response.length);
        apdu.setOutgoingAndSend((short) 0, (short) response.length);
    }

    // GPC v2.3.1 Amd C 3.11.5.2 / Table 3-30: SELECT FCI
    //   6F LL { 84 LA <CRS AID>, A5 LL { 9F08 02 01 00, 80 02 <Global Update Counter> } }
    private void sendFci(APDU apdu, byte[] buffer) {
        byte[] fci = TLV.build(TAG_FCI)
                .add(TAG_FCI_AID, AIDUtil.bytes(JCSystem.getAID()))
                .add(buildProprietaryTemplate())
                .encode();
        Util.arrayCopyNonAtomic(fci, (short) 0, buffer, (short) 0, (short) fci.length);
        apdu.setOutgoingAndSend((short) 0, (short) fci.length);
    }

    static TLV buildProprietaryTemplate() {
        byte[] counter = Simulator.current().gp().getUpdateCounterBytes();
        return TLV.build(TAG_FCI_PROPRIETARY)
                .add(TAG_CRS_VERSION, CRS_VERSION_V1)
                .add(TAG_UPDATE_COUNTER, counter);
    }

    // GPC v2.3.1 Amd C 3.11.3: GET STATUS (Applications). Response is a sequence of 61 templates
    // (4F AID + 9F70 lifecycle: appLifecycle || clState). Oversized responses page via 6310.
    private void handleGetStatus(APDU apdu, byte[] buffer) {
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];
        if (p1 != P1_GET_APPLICATIONS) {
            ISOException.throwIt(SW_INCORRECT_P1P2_VARIANT);
        }
        if ((p2 & P2_RFU_MASK) != 0) {
            ISOException.throwIt(SW_INCORRECT_P1P2_VARIANT);
        }

        try {
            boolean continuation = (p2 & P2_CONTINUATION_FLAG) != 0;
            if (continuation) {
                // GPC v2.3.1 Amd C 3.11.3.2.2: get-next without an in-flight response -> 6985
                if (paging() == null) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
            } else {
                // Initial request: drop any stale cursor before building a new response.
                pagingBuffer[0] = null;
                pagingOffset[0] = 0;
                Query query = parseQuery(apdu, buffer);
                pagingBuffer[0] = buildGetStatusResponse(query);
                pagingOffset[0] = 0;
            }
            sendNextChunk(apdu, buffer);
        } catch (ISOException e) {
            // Keep cursor only for 6310 (more data); any other SW ends the exchange.
            if (e.getReason() != SW_MORE_DATA) {
                pagingBuffer[0] = null;
                pagingOffset[0] = 0;
            }
            throw e;
        } catch (Exception e) {
            // Unexpected failure indicates an engine bug, not bad input.
            pagingBuffer[0] = null;
            pagingOffset[0] = 0;
            log.warn("CRS GET STATUS: unexpected failure", e);
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    // Send next CHUNK_SIZE bytes. Clears cursor + 9000 when exhausted, else throws 6310.
    private void sendNextChunk(APDU apdu, byte[] buffer) {
        byte[] page = paging();
        short remaining = (short) (page.length - pagingOffset[0]);
        short chunk = remaining < CHUNK_SIZE ? remaining : (short) CHUNK_SIZE;
        Util.arrayCopyNonAtomic(page, pagingOffset[0], buffer, (short) 0, chunk);
        pagingOffset[0] += chunk;
        apdu.setOutgoingAndSend((short) 0, chunk);
        if (pagingOffset[0] >= page.length) {
            pagingBuffer[0] = null;
            pagingOffset[0] = 0;
            return;
        }
        ISOException.throwIt(SW_MORE_DATA);
    }

    // GPC v2.3.1 Amd C 3.11.3: the parsed GET STATUS query. aidFilter (mandatory 4F, empty = match all)
    // and AND-combined search criteria pick the rows; tagList (optional 5C) picks the columns, null when
    // absent so all available data is returned.
    private record Query(byte[] aidFilter, List<TLV> criteria, List<Tag> tagList) {
    }

    // GPC v2.3.1 Amd C Table 3-14 / 3-9: data field is 4F (mandatory) + optional 5C tag list + optional
    // AND-filter criteria. Empty 4F value = match all. Any unsupported top-level tag -> 6A80.
    private Query parseQuery(APDU apdu, byte[] buffer) {
        short lc = apdu.setIncomingAndReceive();
        if (lc <= 0) {
            ISOException.throwIt(SW_INCORRECT_VALUES);
        }
        byte[] payload = Arrays.copyOfRange(buffer, ISO7816.OFFSET_CDATA, ISO7816.OFFSET_CDATA + (lc & 0xFFFF));
        byte[] aidFilter = null;
        var criteria = new ArrayList<TLV>();
        List<Tag> tagList = null;
        try {
            for (var t : TLV.parse(payload)) {
                Tag tag = t.tag();
                if (tag.equals(T_AID)) {
                    if (aidFilter != null) {
                        throw new IllegalArgumentException("duplicate 4F search qualifier");
                    }
                    aidFilter = t.value();
                } else if (tag.equals(T_TAG_LIST)) {
                    if (tagList != null) {
                        throw new IllegalArgumentException("duplicate 5C tag list");
                    }
                    tagList = BERTag.parseTags(t.value());
                } else if (isSearchCriterion(tag)) {
                    criteria.add(t);
                } else {
                    throw new IllegalArgumentException("unsupported search qualifier " + tag.toHex());
                }
            }
        } catch (RuntimeException e) {
            log.warn("CRS GET STATUS: malformed query: {}", e.getMessage());
            ISOException.throwIt(SW_INCORRECT_VALUES);
        }
        // GPC v2.3.1 Amd C 3.11.3.2.3: 4F is the mandatory search qualifier.
        if (aidFilter == null) {
            ISOException.throwIt(SW_INCORRECT_VALUES);
        }
        return new Query(aidFilter, criteria, tagList);
    }

    // GPC v2.3.1 Amd C Table 3-9 SC=Yes for the data objects the engine models: 9F70 (CL state) plus the
    // searchable Application Information (87 family, 88 display required). A6 is return-only.
    private static boolean isSearchCriterion(Tag tag) {
        return tag.equals(T_LIFECYCLE)
                || tag.equals(GPData.APPLICATION_FAMILY.tag())
                || tag.equals(GPData.DISPLAY_REQUIRED.tag());
    }

    // GPC v2.3.1 Amd C Tables 3-14 / 3-23: top-level 4F primitives. Throw loud on any other top-level
    // tag; per-AID value-length validation is left to the caller.
    private static List<byte[]> topLevelAidValues(byte[] payload) {
        var out = new ArrayList<byte[]>();
        for (var t : TLV.parse(payload)) {
            if (!t.tag().equals(Tag.ber(TAG_AID))) {
                throw new IllegalArgumentException("unexpected top-level tag " + t.tag().toHex());
            }
            out.add(t.value());
        }
        return out;
    }

    // GPC v2.3.1 Amd C Table 3-15: one 61 template per matching applet. The tag list (when present)
    // selects the returned objects; 4F + 9F70 are always included (Table 3-9).
    private byte[] buildGetStatusResponse(Query query) {
        var templates = new ArrayList<TLV>();
        boolean anyMatch = false;
        boolean anyListedPresent = false;
        for (var entry : Simulator.current().gp().getApplets()) {
            if (entry.getKind() == Kind.PKG || !matches(entry, query)) {
                continue;
            }
            anyMatch = true;
            var template = TLV.build(TAG_APPLICATION_TEMPLATE);
            for (var obj : availableObjects(entry)) {
                boolean always = obj.tag().equals(T_AID) || obj.tag().equals(T_LIFECYCLE);
                boolean listed = query.tagList() != null && containsTag(query.tagList(), obj.tag());
                if (query.tagList() == null || always || listed) {
                    template.add(obj);
                }
                if (listed) {
                    anyListedPresent = true;
                }
            }
            templates.add(template);
        }
        // GPC v2.3.1 Amd C 3.11.3.3.1: with a tag list, no matching entry carrying any listed object is an error.
        if (query.tagList() != null && anyMatch && !anyListedPresent) {
            ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
        }
        return TLV.encode(templates);
    }

    // GPC v2.3.1 Amd C Table 3-9: data objects available for one entry, in response order. 4F + 9F70 + 80
    // are always present (the 80 Application Update Counter is filterable but never unset); Application
    // Information (87, 88, A6) follows when set, with the 88 default applied.
    private static List<TLV> availableObjects(EngineRegistryEntry entry) {
        var objs = new ArrayList<TLV>();
        objs.add(TLV.of(T_AID, AIDUtil.bytes(entry.getAID())));
        objs.add(TLV.of(T_LIFECYCLE, entry.lifecycleState()));
        objs.add(TLV.of(TAG_UPDATE_COUNTER, entry.updateCounterBytes()));
        for (var info : GPData.installInfos()) {
            byte[] v = infoValue(entry, info);
            if (v != null) {
                objs.add(TLV.of(info.tag(), v));
            }
        }
        return objs;
    }

    // Effective Application Information value for GET STATUS: the stored value, or the 88 default when
    // display-required was never installed. null = not available for this entry.
    private static byte[] infoValue(EngineRegistryEntry entry, GPInfo info) {
        byte[] v = entry.infos.get(info);
        if (v != null) {
            return v;
        }
        return info.equals(GPData.DISPLAY_REQUIRED) ? DISPLAY_NOT_REQUIRED : null;
    }

    // GPC v2.3.1 Amd C 3.11.3.2.3: 4F prefix plus the AND-combined search criteria.
    private static boolean matches(EngineRegistryEntry entry, Query query) {
        byte[] aidBytes = AIDUtil.bytes(entry.getAID());
        if (query.aidFilter().length > 0 && !hasPrefix(aidBytes, query.aidFilter())) {
            return false;
        }
        for (var c : query.criteria()) {
            if (!matchesCriterion(entry, c)) {
                return false;
            }
        }
        return true;
    }

    private static boolean matchesCriterion(EngineRegistryEntry entry, TLV criterion) {
        Tag tag = criterion.tag();
        byte[] want = criterion.value();
        // GPC v2.3.1 Amd C 3.11.3.2.3: the application lifecycle byte is ignored; match the CL state byte.
        if (tag.equals(T_LIFECYCLE)) {
            return want.length == 2 && entry.lifecycleState()[1] == want[1];
        }
        for (var info : GPData.installInfos()) {
            if (tag.equals(info.tag())) {
                byte[] have = infoValue(entry, info);
                return have != null && Arrays.equals(have, want);
            }
        }
        return false;
    }

    private static boolean containsTag(List<Tag> tags, Tag tag) {
        for (var t : tags) {
            if (t.equals(tag)) {
                return true;
            }
        }
        return false;
    }

    // GPC v2.3.1 Amd C 3.11.4: SET STATUS (Availability State). P2 = new CL state (00=DEACTIVATED,
    // 01=ACTIVATED). Data is a sequence of 4F AIDs; failures collected into A1 list with 6320.
    private void handleSetStatus(APDU apdu, byte[] buffer) {
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];
        if (p1 != P1_SET_AVAILABILITY) {
            ISOException.throwIt(SW_INCORRECT_P1P2_VARIANT);
        }
        // GPC v2.3.1 Amd C 3.11.4.2.2: NON_ACTIVATABLE is application-only; reject CRS-driven request
        if (p2 == GPCLRegistryEntry.STATE_CL_NON_ACTIVATABLE) {
            ISOException.throwIt(SW_INCORRECT_P1P2_VARIANT);
        }
        if (p2 != GPCLRegistryEntry.STATE_CL_DEACTIVATED && p2 != GPCLRegistryEntry.STATE_CL_ACTIVATED) {
            ISOException.throwIt(SW_INCORRECT_VALUES);
        }

        short lc = apdu.setIncomingAndReceive();
        if (lc <= 0) {
            ISOException.throwIt(SW_INCORRECT_VALUES);
        }
        byte[] payload = Arrays.copyOfRange(buffer, ISO7816.OFFSET_CDATA, ISO7816.OFFSET_CDATA + (lc & 0xFFFF));

        var aidValues = new ArrayList<byte[]>();
        try {
            aidValues.addAll(topLevelAidValues(payload));
        } catch (IllegalArgumentException e) {
            log.warn("CRS SET STATUS: malformed TLV in data field: {}", e.getMessage());
            ISOException.throwIt(SW_INCORRECT_VALUES);
        }
        if (aidValues.isEmpty()) {
            ISOException.throwIt(SW_INCORRECT_VALUES);
        }

        var failed = new ArrayList<byte[]>();
        var sim = Simulator.current();
        for (byte[] aidBytes : aidValues) {
            AID aid;
            try {
                aid = AIDUtil.create(aidBytes);
            } catch (RuntimeException e) {
                failed.add(aidBytes);
                continue;
            }
            var entry = sim.gp().lookup(aid);
            if (entry == null) {
                failed.add(aidBytes);
                continue;
            }
            if (entry.getKind() == Kind.PKG) {
                failed.add(aidBytes);
                continue;
            }
            // GPC v2.3.1 Amd C 3.11.4.3.1: process each AID independently. Catch anything OPEN
            // throws so one bad entry can't truncate the batch (mid-list abort would silently
            // strand the unprocessed tail).
            try {
                // applyCLState bumps the update counter per moved entry (GPC v2.3.1 Amd C 3.11.2.3).
                ContactlessEngine.setCLState(entry, p2);
            } catch (Exception e) {
                // A thrown callback is a real signal worth logging, not just an A1 entry.
                log.warn("CRS SET STATUS: setCLState({}) failed on {}: {}",
                        Integer.toHexString(p2 & 0xFF), aid, e.toString());
                failed.add(aidBytes);
            }
        }

        if (failed.isEmpty()) {
            apdu.setOutgoingAndSend((short) 0, (short) 0);
            return;
        }

        // GPC v2.3.1 Amd C 3.11.4.3.1: A1 template of failed AIDs, then warning 6320 (Table 3-28)
        var list = TLV.build(TAG_FAILED_APPS);
        for (var aidBytes : failed) {
            list.add(TAG_AID, aidBytes);
        }
        byte[] response = list.encode();
        int budget = buffer.length - 2;
        if (response.length > budget) {
            log.warn("CRS SET STATUS: A1 response {} bytes exceeds buffer budget {}", response.length, budget);
            ISOException.throwIt(SW_FILE_FULL);
        }
        Util.arrayCopyNonAtomic(response, (short) 0, buffer, (short) 0, (short) response.length);
        apdu.setOutgoingAndSend((short) 0, (short) response.length);
        ISOException.throwIt(SW_PARTIAL_FAILURE);
    }

    // GPC v2.3.1 Amd C 3.11: SIO exposed only on platform fetch (clientAID == null), never A2A.
    @Override
    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
        if (clientAID == null && (parameter == GPCLSystem.GPCL_CRS_APPLICATION || parameter == GPCLSystem.GPCL_CREL_APPLICATION)) {
            return this;
        }
        return null;
    }

    @Override
    public boolean processCLRequest(GPRegistryEntry requester, GPCLRegistryEntry target, short event) {
        if (event != CLAppletEvent.EVENT_ACTIVATED) {
            // Engine does not model volatile priority (the other defined trigger).
            log.debug("CRS processCLRequest: ignoring event 0x{}", Integer.toHexString(event & 0xFFFF));
            return false;
        }

        target.setCLState(GPCLRegistryEntry.STATE_CL_ACTIVATED);
        return true;
    }

    // CRELApplication contract: platform CRS is on no CREL list, so no-op.
    @Override
    public void notifyCLEvent(GPCLRegistryEntry source, short event) {
        // no-op
    }

    private static boolean hasPrefix(byte[] aid, byte[] prefix) {
        if (prefix.length > aid.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (aid[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }
}
