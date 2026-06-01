// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import org.globalplatform.contactless.CLAppletEvent;
import org.globalplatform.contactless.GPCLRegistryEntry;
import pro.javacard.engine.globalplatform.GPNamedElement.GPInfo;
import pro.javacard.engine.globalplatform.GPNamedElement.GPTag;
import pro.javacard.tlv.Tag;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

// Central registry and single definition site for GP data objects (GPTag): BER-TLV tags the engine
// stores, encodes or retrieves. Looked up by tag; name() is the spec name, used for display only.
// Pure Java, no JC runtime. Keys are value-based, so Tag and GPTag map correctly.
public final class GPData {

    private static final Map<Integer, GPTag> BY_TAG = new LinkedHashMap<>();

    // Define a GP data object and index it by tag. Rejects a duplicate tag. name() is for display.
    private static GPTag tag(String name, int ber) {
        var element = new GPTag(name, Tag.ber(ber));
        if (BY_TAG.put(ber, element) != null) {
            throw new IllegalStateException("Duplicate GP data object tag: " + name);
        }
        return element;
    }

    // GET STATUS / GlobalPlatform Registry related data (GPC v2.3.1 Table 11-36 / 11-37). name() is
    // the official spec name; 0x84 here is the Executable Module AID (its GET STATUS meaning, not the
    // SELECT FCI "DF Name" - see docs/gp-data-objects.md on context-scoped tags).
    public static final GPTag REGISTRY_DATA = tag("GlobalPlatform Registry related data", 0xE3);
    public static final GPTag AID = tag("AID", 0x4F);
    public static final GPTag LIFECYCLE_STATE = tag("Life Cycle State", 0x9F70);
    public static final GPTag PRIVILEGES = tag("Privileges", 0xC5);
    public static final GPTag LOAD_FILE_AID = tag("Application's Executable Load File AID", 0xC4);
    public static final GPTag ASSOCIATED_SD_AID = tag("Associated Security Domain's AID", 0xCC);
    public static final GPTag EXECUTABLE_MODULE_AID = tag("Executable Module AID", 0x84);
    public static final GPTag IMPLICIT_SELECTION_PARAMETER = tag("Implicit Selection Parameter", 0xCF);
    public static final GPTag LOAD_FILE_VERSION = tag("Executable Load File Version Number", 0xCE);

    // INSTALL EF System Specific Parameters (GPC v2.3.1 Table 11-49). Stored opaque (parse, don't
    // validate): the engine models neither memory quotas nor [TS 102 226]. CB drives global service
    // registration (8.1.1); CF (Implicit Selection Parameter) is defined above.
    public static final GPTag GLOBAL_SERVICE_PARAMETERS = tag("Global Service Parameters", 0xCB);
    public static final GPTag VOLATILE_MEMORY_QUOTA = tag("Volatile Memory Quota", 0xC7);
    public static final GPTag NON_VOLATILE_MEMORY_QUOTA = tag("Non-volatile Memory Quota", 0xC8);
    public static final GPTag VOLATILE_RESERVED_MEMORY = tag("Volatile Reserved Memory", 0xD7);
    public static final GPTag NON_VOLATILE_RESERVED_MEMORY = tag("Non-volatile Reserved Memory", 0xD8);
    public static final GPTag TS_102_226_PARAMETER = tag("[TS 102 226] parameter", 0xCA);

    // GET DATA data objects an SD must/may support (GPC v2.3.1 11.3, authoritative list 11.3.x).
    public static final GPTag IIN = tag("Issuer Identification Number", 0x42);
    public static final GPTag CARD_IMAGE_NUMBER = tag("Card Image Number", 0x45);
    public static final GPTag CARD_DATA = tag("Card Data", 0x66);
    public static final GPTag CARD_RECOGNITION_DATA = tag("Card Recognition Data", 0x73);
    public static final GPTag CARD_CAPABILITY_INFORMATION = tag("Card Capability Information", 0x67);
    public static final GPTag CURRENT_SECURITY_LEVEL = tag("Current Security Level", 0xD3);
    public static final GPTag EXTENDED_CARD_RESOURCES = tag("Extended Card Resources Information", 0xFF21);
    public static final GPTag SD_MANAGER_URL = tag("Security Domain Manager URL", 0x5F50);
    public static final GPTag CONFIRMATION_COUNTER = tag("Confirmation Counter", 0xC2);
    public static final GPTag SEQUENCE_COUNTER = tag("Sequence Counter of the default Key Version Number", 0xC1);
    // 2F00 (List of Applications, GPC 11.3.3.1.3) is an EF.DIR file id, not a BER-TLV tag - excluded.

    // Further GET DATA / response data objects (GPC v2.3.1 ch. 11).
    public static final GPTag MAX_COMMAND_DATA_LENGTH = tag("Maximum length of data field in command message", 0x9F65);
    public static final GPTag TAG_LIST = tag("Tag list", 0x5C);
    public static final GPTag APPLICATION_PROVIDER_ID = tag("Application Provider Identifier", 0x5F20);
    public static final GPTag APPLICATION_TEMPLATE = tag("Application Template", 0x61);

    // Card Production Life Cycle data; not a GPC v2.3.1 tag (legacy/EMV). The perso/pre-perso slices
    // are engine conventions for STORE DATA writes (see docs/gp-data-objects.md).
    public static final GPTag CPLC = tag("Card Production Life Cycle Data", 0x9F7F);
    public static final GPTag CPLC_PERSO_SLICE = tag("CPLC perso slice", 0x9F66);
    public static final GPTag CPLC_PREPERSO_SLICE = tag("CPLC pre-perso slice", 0x9F67);

    // Key Information Template (GPC v2.3.1 11.3.3.1.1, Table 11-28); computed from the SD's keys, not stored.
    public static final GPTag KEY_INFORMATION_TEMPLATE = tag("Key Information Template", 0xE0);

    public static Optional<GPTag> byTag(int tag) {
        return Optional.ofNullable(BY_TAG.get(tag));
    }

    // ---- Contactless Application Information (GPC v2.3.1 Amd C 11.2.3), keyed by GPCL INFO id ----

    private static final Map<Short, GPInfo> BY_INFO = new LinkedHashMap<>();

    // info with an INSTALL [for install] A1 sub-tag (bridged on install); reject a duplicate INFO id.
    private static GPInfo info(String name, short id, int a1Tag, short event) {
        return register(new GPInfo(name, id, Tag.ber(a1Tag), event));
    }

    // info set only via setInfo (no install A1 sub-tag).
    private static GPInfo info(String name, short id, short event) {
        return register(new GPInfo(name, id, null, event));
    }

    private static GPInfo register(GPInfo element) {
        if (BY_INFO.put(element.info(), element) != null) {
            throw new IllegalStateException("Duplicate GP info element: " + element.name());
        }
        return element;
    }

    public static final GPInfo APPLICATION_FAMILY = info("Application Family", GPCLRegistryEntry.INFO_FAMILY_IDENTIFIER, 0x87, CLAppletEvent.EVENT_FAMILY_IDENTIFIER);
    public static final GPInfo DISPLAY_REQUIRED = info("Display Required Indicator", GPCLRegistryEntry.INFO_DISPLAY_REQUIREMENT, 0x88, CLAppletEvent.EVENT_DISPLAY_REQUIREMENT);
    public static final GPInfo DISCRETIONARY_DATA = info("Discretionary Data", GPCLRegistryEntry.INFO_DISCRETIONARY_DATA, CLAppletEvent.EVENT_DISCRETIONARY_DATA);

    public static Optional<GPInfo> byInfo(short info) {
        return Optional.ofNullable(BY_INFO.get(info));
    }

    // CL info elements carrying an install A1 sub-tag - the source of the install tag->info bridge.
    public static Collection<GPInfo> installInfos() {
        return BY_INFO.values().stream().filter(i -> i.tag() != null).toList();
    }

    private GPData() {
    }
}
