// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import apdu4j.core.CommandAPDU;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.gp.GPCrypto;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPKeyInfo;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.keys.PlaintextKeys;

import java.io.ByteArrayOutputStream;
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

        // 1. Fresh sim - KIT shows 3 KIDs (ENC/MAC/DEK) all at the factory KVN=0xFF.
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo, mode);
            var kit = gp.getKeyInfoTemplate();
            assertEquals(3, kit.size());
            assertTrue(allAtKvn(kit, 0xFF));
        }

        // 2. PUT KEY add of KVN=0x01 with master_A - factory KVN=0xFF is evicted (engine
        // factory-removal trigger; GPC v2.3.1 11.8 is silent on factory removal).
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo, mode);
            addKvn(gp, 0x01, MasterKeys.A);
            var kit = gp.getKeyInfoTemplate();
            assertEquals(3, kit.size());
            assertTrue(allAtKvn(kit, 0x01));
        }

        // 3. Explicit setVersion(0xFF) forces IU P1=0xFF; the engine no longer holds KVN=0xFF
        // so EXTERNAL_AUTHENTICATE must fail (factory-removal rule made the slot disappear).
        try (var bibo = sim.connect()) {
            var gp = GPSession.discover(bibo);
            var explicitFactory = PlaintextKeys.defaultKey();
            explicitFactory.setVersion(0xFF);
            assertThrows(GPException.class,
                    () -> gp.openSecureChannel(explicitFactory, null, null, mode));
        }

        // 4. IU P1=0 (kvn=0 leaves setVersion unset) - newest-selection picks the only keyset 0x01.
        try (var bibo = sim.connect()) {
            var gp = openSdAt(bibo, SecurityDomainApplet.OPEN_AID, MasterKeys.A, 0, mode);
            assertEquals(3, gp.getKeyInfoTemplate().size());
        }

        // 5. PUT KEY add of KVN=0x02 with master_B alongside 0x01 (no factory trigger: factory
        // already gone). KIT now shows 6 entries: 3 KIDs at 0x01 plus 3 KIDs at 0x02.
        try (var bibo = sim.connect()) {
            var gp = openSdAt(bibo, SecurityDomainApplet.OPEN_AID, MasterKeys.A, 0x01, mode);
            addKvn(gp, 0x02, MasterKeys.B);
            var kit = gp.getKeyInfoTemplate();
            assertEquals(6, kit.size());
            assertEquals(3, countAtKvn(kit, 0x01));
            assertEquals(3, countAtKvn(kit, 0x02));
        }

        // 6. IU P1=0 with master_B - newest-selection now resolves to KVN=0x02 (the most-recently
        // added keyset wins; insertion-order, not lowest-KVN).
        try (var bibo = sim.connect()) {
            openSdAt(bibo, SecurityDomainApplet.OPEN_AID, MasterKeys.B, 0, mode);
        }

        // 7. Explicit setVersion(0x01) bypasses newest-selection and authenticates against the
        // older KVN - explicit P1 always wins over newest-pick.
        try (var bibo = sim.connect()) {
            openSdAt(bibo, SecurityDomainApplet.OPEN_AID, MasterKeys.A, 0x01, mode);
        }

        // 8. PUT KEY replace at KVN=0x01 with master_C - old master_A no longer authenticates,
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
                    () -> gp.openSecureChannel(stale, null, null, mode));
        }
        try (var bibo = sim.connect()) {
            openSdAt(bibo, SecurityDomainApplet.OPEN_AID, MasterKeys.C, 0x01, mode);
        }

        // 9. DELETE [key] for KVN=0x02 - KIT must lose all KIDs under 0x02; master_B no longer
        // authenticates. Per-KVN deletion grain (engine model; GPC v2.3.1 11.2.2.3.2).
        try (var bibo = sim.connect()) {
            var gp = openSdAt(bibo, SecurityDomainApplet.OPEN_AID, MasterKeys.C, 0x01, mode);
            gp.deleteKey(0x02, null);
            var kit = gp.getKeyInfoTemplate();
            assertEquals(3, kit.size());
            assertEquals(0, countAtKvn(kit, 0x02));
        }
        try (var bibo = sim.connect()) {
            var gp = GPSession.connect(bibo, GPTestUtils.gpAID(SecurityDomainApplet.OPEN_AID));
            var deleted = PlaintextKeys.fromMasterKey(MasterKeys.B);
            deleted.setVersion(0x02);
            assertThrows(GPException.class,
                    () -> gp.openSecureChannel(deleted, null, null, mode));
        }

        // 10. PUT KEY at KVN=0xFF must be universally rejected - engine restricts the PUT KEY
        // KVN range to 0x01..0x7F (factory slot is reserved for boot-time seeding only).
        try (var bibo = sim.connect()) {
            var gp = openSdAt(bibo, SecurityDomainApplet.OPEN_AID, MasterKeys.C, 0x01, mode);
            var atFactory = PlaintextKeys.fromMasterKey(MasterKeys.A);
            atFactory.setVersion(0xFF);
            assertThrows(GPException.class,
                    () -> gp.putKeys(atFactory, true));
        }

        // 11. PUT KEY add (replace=false) for an already-existing KVN must be rejected so the
        // caller is forced to use replace=true, since GPC v2.3.1 11.8.2.1 says P1='00' adds a new
        // keyset while non-zero P1 replaces an existing one and the engine rejects an "add"
        // against an already-present KVN.
        try (var bibo = sim.connect()) {
            var gp = openSdAt(bibo, SecurityDomainApplet.OPEN_AID, MasterKeys.C, 0x01, mode);
            assertThrows(GPException.class,
                    () -> addKvn(gp, 0x01, MasterKeys.B));
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
            // SW_FUNC_NOT_SUPPORTED
            assertEquals(0x6A81, ex.sw);
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
            // SW_REFERENCED_DATA_NOT_FOUND
            assertEquals(0x6A88, ex.sw);
        }
    }

    // PUT KEY body-level guards (GPC v2.3.1 11.8). gp-pro's putKeys only builds well-formed
    // commands, so each malformed case is hand-assembled (valid DEK-encrypted AES-16 blocks via
    // gp.encryptDEK) and sent through the SCP-wrapped channel with gp.transmit. One channel carries
    // every probe: a rejected PUT KEY leaves the SCP sequence counter untouched (only a successful
    // PUT KEY resets it, GPC v2.3.1 E.1.2), and the lone addKvn resets host and card symmetrically.
    @Test
    void putKeyBodyRejects() throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        byte[] key16 = MasterKeys.A;

        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);

            // KCV length 0 - mandatory for DES/AES (GPC v2.3.1 11.8.2.3.3) -> 6A80.
            // P1=00 add, KVN=05, P2=81 (multi-key flag, first KID=01), single block.
            assertEquals(0x6A80, gp.transmit(putKey(0x00, 0x81, 0x05, aesBlockNoKcv(gp, key16))).getSW());

            // KCV does not match the key value (GPC v2.3.1 11.8.3.2 Table 11-78) -> 6982.
            assertEquals(0x6982, gp.transmit(putKey(0x00, 0x81, 0x05, aesBlock(gp, key16, new byte[]{0x00, 0x00, 0x00}))).getSW());

            // Consecutive KIDs must stay within 00..7F (GPC v2.3.1 11.8.2.2). First KID 0x7F + a second
            // block makes the next KID 0x80, out of range -> 6A80 (the second block is never parsed).
            var body = concat(aesBlock(gp, key16, GPCrypto.kcv_aes(key16)), new byte[]{(byte) 0x80, 0x01, 0x00});
            assertEquals(0x6A80, gp.transmit(putKey(0x00, 0xFF, 0x06, body)).getSW());

            // The replace-path guards need an existing keyset. Add a real KVN=0x10 (AES, KIDs 1/2/3) -
            // the only successful PUT KEY here, so the only point the SCP counter resets.
            addKvn(gp, 0x10, MasterKeys.A);

            // Replacing a KVN with a block whose KID is absent from the existing keyset
            // (GPC v2.3.1 11.8.2.3.3) -> 6A88. KVN 0x10 holds KIDs 1/2/3; first KID 0x05 is absent.
            var miss = aesBlock(gp, key16, GPCrypto.kcv_aes(key16));
            assertEquals(0x6A88, gp.transmit(putKey(0x10, 0x85, 0x10, miss)).getSW()); // P2=85: first KID=05

            // A replacement key must keep the existing type and length (GPC v2.3.1 11.8.2.3.3) -> 6A80.
            // Existing KID 1 at KVN 0x10 is AES-16; replace it with an AES-32 block.
            byte[] key32 = concat(key16, key16); // a 32-byte AES key value
            var widen = aesBlock(gp, key32, GPCrypto.kcv_aes(key32));
            assertEquals(0x6A80, gp.transmit(putKey(0x10, 0x81, 0x10, widen)).getSW()); // P2=81: first KID=01 (AES-16)
        }
    }

    // Assemble a PUT KEY command (CLA 80, INS D8). Body = newKVN || keyBlocks.
    private static CommandAPDU putKey(int p1, int p2, int kvn, byte[] blocks) {
        return new CommandAPDU(0x80, 0xD8, p1, p2, concat(new byte[]{(byte) kvn}, blocks));
    }

    // A valid AES key component block: 88 || blockLen || actualKeyLen || DEK-cgram || kcvLen || kcv.
    // The cgram is the key value DEK-encrypted exactly as gp-pro's encodeKey does (gp.encryptDEK).
    private static byte[] aesBlock(GPSession gp, byte[] keyValue, byte[] kcv) throws Exception {
        byte[] cgram = gp.encryptDEK(keyValue); // AES-CBC under the session DEK
        var bo = new ByteArrayOutputStream();
        bo.write(0x88);                  // GPKey.AES type
        bo.write(cgram.length + 1);      // block length (+1 for the actual-key-length byte)
        bo.write(keyValue.length);       // actual key length
        bo.writeBytes(cgram);
        bo.write(kcv.length);
        bo.writeBytes(kcv);
        return bo.toByteArray();
    }

    // Same AES block but with a zero-length KCV field (kcvLen=0, no KCV bytes).
    private static byte[] aesBlockNoKcv(GPSession gp, byte[] keyValue) throws Exception {
        byte[] cgram = gp.encryptDEK(keyValue);
        var bo = new ByteArrayOutputStream();
        bo.write(0x88);
        bo.write(cgram.length + 1);
        bo.write(keyValue.length);
        bo.writeBytes(cgram);
        bo.write(0x00);                  // kcvLen = 0
        return bo.toByteArray();
    }

    private static byte[] concat(byte[] a, byte[] b) {
        var bo = new ByteArrayOutputStream();
        bo.writeBytes(a);
        bo.writeBytes(b);
        return bo.toByteArray();
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
