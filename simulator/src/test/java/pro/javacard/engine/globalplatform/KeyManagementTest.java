// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPKeyInfo;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.keys.PlaintextKeys;

import java.util.EnumSet;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.javacard.engine.globalplatform.GPTestUtils.MasterKeys;
import static pro.javacard.engine.globalplatform.GPTestUtils.addKvn;
import static pro.javacard.engine.globalplatform.GPTestUtils.openIsd;
import static pro.javacard.engine.globalplatform.GPTestUtils.openSdAt;
import static pro.javacard.engine.globalplatform.GPTestUtils.replaceKvn;

// Single end-to-end narrative covering the ISD keystore lifecycle: factory KVN=0xFF eviction,
// PUT KEY add/replace, newest-keyset selection (IU P1=0), DELETE [key] per-KVN, and the
// engine's two PUT KEY range/collision rules. Replaces FactoryKeyTest, PutKeyTest,
// DeleteKeyTest, NewestKeysetTest. Observability is wire-only via gp.getKeyInfoTemplate().
public class KeyManagementTest {

    // Mirrors PutKeyTest.scpConfigs(): SCP02 and SCP03 via gp-pro's MAC mode.
    static Stream<Arguments> scpConfigs() {
        return Stream.of(
                Arguments.of("SCP02", (Supplier<SCPConfig>) SCPConfig.SCP02::new, EnumSet.of(GPSession.APDUMode.MAC)),
                Arguments.of("SCP03", (Supplier<SCPConfig>) SCPConfig.SCP03::new, EnumSet.of(GPSession.APDUMode.MAC))
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("scpConfigs")
    void fullKeystoreLifecycle(String name, Supplier<SCPConfig> cfgFactory, EnumSet<GPSession.APDUMode> mode) throws Exception {
        var sim = new JavaCardEngine.Builder().withSCP(cfgFactory.get()).build();

        // 1. Fresh sim — KIT shows 3 KIDs (ENC/MAC/DEK) all at the factory KVN=0xFF.
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo, mode);
            var kit = gp.getKeyInfoTemplate();
            assertEquals(3, kit.size(), "fresh ISD must expose exactly the 3-KID factory keyset (SCP02/SCP03 convention; GPC v2.3.1 Appendix E + 11.1.9 KVN coding)");
            assertTrue(allAtKvn(kit, 0xFF), "fresh ISD KIT must report all 3 KIDs at the factory KVN=0xFF");
        }

        // 2. PUT KEY add of KVN=0x01 with master_A — factory KVN=0xFF is evicted (engine
        // factory-removal trigger; GPC v2.3.1 11.8 is silent on factory removal).
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo, mode);
            addKvn(gp, 0x01, MasterKeys.A);
            var kit = gp.getKeyInfoTemplate();
            assertEquals(3, kit.size(), "factory KVN 0xFF must disappear after first non-factory PUT KEY add (engine convention; GPC v2.3.1 11.8 silent)");
            assertTrue(allAtKvn(kit, 0x01), "after factory eviction, KIT must show only the new KVN=0x01");
        }

        // 3. Explicit setVersion(0xFF) forces IU P1=0xFF; the engine no longer holds KVN=0xFF
        // so EXTERNAL_AUTHENTICATE must fail (factory-removal rule made the slot disappear).
        try (var bibo = sim.connect()) {
            var gp = GPSession.discover(bibo);
            var explicitFactory = PlaintextKeys.defaultKey();
            explicitFactory.setVersion(0xFF);
            assertThrows(GPException.class,
                    () -> gp.openSecureChannel(explicitFactory, null, null, mode),
                    "factory KVN 0xFF must no longer authenticate after first non-factory PUT KEY add (engine factory-removal rule)");
        }

        // 4. IU P1=0 (kvn=0 leaves setVersion unset) — newest-selection picks the only keyset 0x01.
        try (var bibo = sim.connect()) {
            var gp = openSdAt(bibo, SecurityDomainApplet.OPEN_AID, MasterKeys.A, 0, mode);
            assertEquals(3, gp.getKeyInfoTemplate().size(), "IU P1=0 must resolve to KVN=0x01 (newest-keyset selection; GPC v2.3.1 D.4.1.3 implementation-defined)");
        }

        // 5. PUT KEY add of KVN=0x02 with master_B alongside 0x01 (no factory trigger: factory
        // already gone). KIT now shows 6 entries: 3 KIDs at 0x01 plus 3 KIDs at 0x02.
        try (var bibo = sim.connect()) {
            var gp = openSdAt(bibo, SecurityDomainApplet.OPEN_AID, MasterKeys.A, 0x01, mode);
            addKvn(gp, 0x02, MasterKeys.B);
            var kit = gp.getKeyInfoTemplate();
            assertEquals(6, kit.size(), "two coexisting non-factory keysets must yield 3+3=6 KIT entries (no factory re-trigger; GPC v2.3.1 11.8)");
            assertEquals(3, countAtKvn(kit, 0x01), "KVN=0x01 keyset must remain after add of KVN=0x02");
            assertEquals(3, countAtKvn(kit, 0x02), "KVN=0x02 keyset must be present after add");
        }

        // 6. IU P1=0 with master_B — newest-selection now resolves to KVN=0x02 (the most-recently
        // added keyset wins; insertion-order, not lowest-KVN).
        try (var bibo = sim.connect()) {
            openSdAt(bibo, SecurityDomainApplet.OPEN_AID, MasterKeys.B, 0, mode);
        }

        // 7. Explicit setVersion(0x01) bypasses newest-selection and authenticates against the
        // older KVN — explicit P1 always wins over newest-pick.
        try (var bibo = sim.connect()) {
            openSdAt(bibo, SecurityDomainApplet.OPEN_AID, MasterKeys.A, 0x01, mode);
        }

        // 8. PUT KEY replace at KVN=0x01 with master_C — old master_A no longer authenticates,
        // master_C does. KVN slot stays the same; only the underlying ENC/MAC/DEK triple changes.
        try (var bibo = sim.connect()) {
            var gp = openSdAt(bibo, SecurityDomainApplet.OPEN_AID, MasterKeys.A, 0x01, mode);
            replaceKvn(gp, 0x01, MasterKeys.C);
        }
        try (var bibo = sim.connect()) {
            var gp = GPSession.connect(bibo, GPTestUtils.gpAID(SecurityDomainApplet.OPEN_AID));
            var stale = PlaintextKeys.fromMasterKey(MasterKeys.A);
            stale.setVersion(0x01);
            assertThrows(GPException.class,
                    () -> gp.openSecureChannel(stale, null, null, mode),
                    "PUT KEY replace at KVN=0x01 must invalidate the prior master (GPC v2.3.1 11.8.2.1: P1=KVN identifies an existing keyset to be replaced)");
        }
        try (var bibo = sim.connect()) {
            openSdAt(bibo, SecurityDomainApplet.OPEN_AID, MasterKeys.C, 0x01, mode);
        }

        // 9. DELETE [key] for KVN=0x02 — KIT must lose all KIDs under 0x02; master_B no longer
        // authenticates. Per-KVN deletion grain (engine model; GPC v2.3.1 11.2.2.3.2).
        try (var bibo = sim.connect()) {
            var gp = openSdAt(bibo, SecurityDomainApplet.OPEN_AID, MasterKeys.C, 0x01, mode);
            gp.deleteKey(0x02, null);
            var kit = gp.getKeyInfoTemplate();
            assertEquals(3, kit.size(), "after DELETE [key] of KVN=0x02 only the surviving KVN=0x01 (3 KIDs) must remain");
            assertEquals(0, countAtKvn(kit, 0x02), "DELETE [key] with D2=0x02 must remove every KID under that KVN");
        }
        try (var bibo = sim.connect()) {
            var gp = GPSession.connect(bibo, GPTestUtils.gpAID(SecurityDomainApplet.OPEN_AID));
            var deleted = PlaintextKeys.fromMasterKey(MasterKeys.B);
            deleted.setVersion(0x02);
            assertThrows(GPException.class,
                    () -> gp.openSecureChannel(deleted, null, null, mode),
                    "deleted KVN=0x02 must no longer authenticate after DELETE [key] (GPC v2.3.1 11.2.2.3.2)");
        }

        // 10. PUT KEY at KVN=0xFF must be universally rejected — engine restricts the PUT KEY
        // KVN range to 0x01..0x7F (factory slot is reserved for boot-time seeding only).
        try (var bibo = sim.connect()) {
            var gp = openSdAt(bibo, SecurityDomainApplet.OPEN_AID, MasterKeys.C, 0x01, mode);
            var atFactory = PlaintextKeys.fromMasterKey(MasterKeys.A);
            atFactory.setVersion(0xFF);
            assertThrows(GPException.class,
                    () -> gp.putKeys(atFactory, true),
                    "PUT KEY at KVN=0xFF must be rejected — KVN range is 0x01..0x7F (engine rule)");
        }

        // 11. PUT KEY add (replace=false) for an already-existing KVN must be rejected so the
        // caller is forced to use replace=true, since GPC v2.3.1 11.8.2.1 says P1='00' adds a new
        // keyset while non-zero P1 replaces an existing one and the engine rejects an "add"
        // against an already-present KVN.
        try (var bibo = sim.connect()) {
            var gp = openSdAt(bibo, SecurityDomainApplet.OPEN_AID, MasterKeys.C, 0x01, mode);
            assertThrows(GPException.class,
                    () -> addKvn(gp, 0x01, MasterKeys.B),
                    "PUT KEY add for an existing KVN must be rejected (GPC v2.3.1 11.8.2.1)");
        }
    }

    // DELETE [key] with 'D0' (Key Identifier) alone: engine has no per-KID deletion model; the
    // KeySet is an atomic ENC/MAC/DEK triple. Reject with SW_FUNC_NOT_SUPPORTED rather than
    // silently widen to whole-KVN deletion. GPC v2.3.1 11.2.2.3.2.
    @Test
    void deleteByKidAloneRejected() throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            var ex = assertThrows(GPException.class, () -> gp.deleteKey(null, 0x01));
            assertEquals(0x6A81, ex.sw, "DELETE [key] by 'D0' alone must yield SW_FUNC_NOT_SUPPORTED (0x6A81) per GPC v2.3.1 11.2.2.3.2");
        }
    }

    // DELETE [key] with an unknown KVN: gp-pro's deleteKey throws GPException carrying the
    // card's SW_REFERENCED_DATA_NOT_FOUND (0x6A88). GPC v2.3.1 11.2.3.2 / Table 11-26.
    @Test
    void deleteUnknownKvnRejected() throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            var ex = assertThrows(GPException.class, () -> gp.deleteKey(0x55, null));
            assertEquals(0x6A88, ex.sw, "unknown KVN must yield SW_REFERENCED_DATA_NOT_FOUND (0x6A88) per GPC v2.3.1 11.2.3.2 / Table 11-26");
        }
    }

    // True iff every entry in the KIT carries the given KVN. Drives the factory-eviction and
    // post-add assertions purely off wire-visible state.
    private static boolean allAtKvn(List<GPKeyInfo> kit, int kvn) {
        return kit.stream().allMatch(k -> k.getVersion() == kvn);
    }

    // Count of KIT entries at the given KVN. Lets multi-keyset assertions be expressed as
    // simple integer comparisons against the expected 3-KID-per-KVN layout.
    private static long countAtKvn(List<GPKeyInfo> kit, int kvn) {
        return kit.stream().filter(k -> k.getVersion() == kvn).count();
    }
}
