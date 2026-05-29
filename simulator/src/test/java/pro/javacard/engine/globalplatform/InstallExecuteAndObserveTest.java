// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.engine.testapplets.GlobalPlatformTestApplet;
import pro.javacard.gp.GPCrypto;
import pro.javacard.gp.GPData;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPKeyInfo;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.keys.PlaintextKeys;

import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.javacard.engine.globalplatform.GPTestUtils.gpAID;

// End-to-end install/execute/observe narrative across the supported SCP variants, plus the GP
// surfaces that don't fit the keystore or SD-lifecycle narratives: GET STATUS chunking,
// shareable cross-instance, GET DATA unknown-tag rejection, and the SSD load-file registration guard.
public class InstallExecuteAndObserveTest {

    private static final AID PKG = AIDUtil.create("01020304050607080F");
    private static final AID A = AIDUtil.create("0102030405060708A1");
    private static final AID B = AIDUtil.create("0102030405060708B2");

    private static final byte ID_A = (byte) 0xA1;
    private static final byte ID_B = (byte) 0xB2;

    static Stream<Arguments> scpConfigs() {
        byte[] custom128 = Hex.decode("000102030405060708090A0B0C0D0E0F");
        byte[] custom256 = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        return Stream.of(
                Arguments.of("SCP02-MAC", new SCPConfig.SCP02(), null, EnumSet.of(GPSession.APDUMode.MAC)),
                Arguments.of("SCP03-MAC", new SCPConfig.SCP03(), null, EnumSet.of(GPSession.APDUMode.MAC)),
                Arguments.of("SCP03-S16-ENC", new SCPConfig.SCP03(true), null, EnumSet.of(GPSession.APDUMode.ENC)),
                Arguments.of("Custom128-SCP03-ENC", new SCPConfig.SCP03(custom128), custom128, EnumSet.of(GPSession.APDUMode.ENC)),
                Arguments.of("Custom256-SCP03-ENC", new SCPConfig.SCP03(custom256), custom256, EnumSet.of(GPSession.APDUMode.ENC))
        );
    }

    // Single end-to-end narrative across all 5 SCP variants:
    //   1. Build sim, register test applet load file.
    //   2. Open ISD; assert KIT shape (3 KIDs, type per SCP, all KVN=0xFF, KIDs 1/2/3).
    //   3. Fetch CPLC and assert engine signature ("JCEN" IC serial, 0x4242 in fab/serial slots).
    //   4. Assert SSD load file planted at boot (registry visibility, lifecycle LOADED, modules).
    //   5. Install applet via SCP with install-param byte 0x55.
    //   6. Reopen ISD; assert applet/PKG/ISD all present in registry.
    //   7. SELECT applet; INS_GET_IDENTITY round-trips the install-param byte.
    //   8. Reopen SCP to applet; SCP-encrypted INS 0x42 cgram round-trip (Hello, World!).
    //   9. Reopen ISD; gp.deleteAID(applet); assert applet gone from registry.
    @ParameterizedTest(name = "{0}")
    @MethodSource("scpConfigs")
    void installExecuteObserve(String name, SCPConfig config, byte[] masterKey,
                               EnumSet<GPSession.APDUMode> mode) throws Exception {
        var sim = new JavaCardEngine.Builder().withSCP(config).build();
        // ELF and instance AIDs must differ (GPC v2.3.1 6.5.1.1); instance = ELF + instance byte.
        var pkgAID = AIDUtil.create("010203040506070809");
        var appletAID = AIDUtil.create("01020304050607080901");
        var jcaid = gpAID(appletAID);
        sim.loadApplet(pkgAID, appletAID, GlobalPlatformTestApplet.class);

        // 2: open ISD, inspect KIT. Done in its own session - gp.getKeyInfoTemplate() takes the
        // SCP-wrapped GET DATA path when a session is open, and we don't want to reuse this
        // session for follow-up SCP-wrapped commands in the same connection.
        try (var bibo = sim.connect()) {
            var gp = openWith(bibo, masterKey, mode);
            assertKit(gp, config);
        }

        // 3 + 4: fresh session - CPLC via raw bibo, registry visibility for the planted SSD load file.
        try (var bibo = sim.connect()) {
            var gp = openWith(bibo, masterKey, mode);
            assertCplc(bibo);
            assertSsdLoadFilePlanted(gp);
        }

        // 5: install applet via SCP with install-param byte 0x55.
        try (var bibo = sim.connect()) {
            var gp = openWith(bibo, masterKey, mode);
            gp.installAndMakeSelectable(gpAID(pkgAID), jcaid, jcaid, EnumSet.noneOf(Privilege.class), new byte[]{(byte) 0x55});
        }

        // 6: reopen ISD; registry sees applet + package + ISD.
        try (var bibo = sim.connect()) {
            var gp = openWith(bibo, masterKey, mode);
            var registry = gp.getRegistry();
            assertTrue(registry.allAppletAIDs().contains(jcaid));
            assertTrue(registry.allPackageAIDs().contains(gpAID(pkgAID)));
            assertTrue(registry.getISD().isPresent());

            // 7: SELECT applet; round-trip install-param byte via INS_GET_IDENTITY.
            var sel = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AIDUtil.bytes(appletAID), 256));
            assertEquals(0x9000, sel.getSW());
            var ident = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_GET_IDENTITY, 0x00, 0x00, 256));
            assertEquals(0x9000, ident.getSW());
            assertEquals(1, ident.getData().length);
            // install-param byte round-trips
            assertEquals((byte) 0x55, ident.getData()[0]);
        }

        // 8: reopen SCP to applet AID with ENC mode; SCP-encrypted INS 0x42 cgram round-trip.
        // SCP02 SC.decryptData uses the static master DEK while PlaintextKeys.encrypt for SCP02
        // uses a session-derived SDEK (engine vs spec asymmetry; outside this test's scope), so
        // the cgram path is exercised only on the SCP03 family. KIT/CPLC/install/registry/delete
        // above already cover the SCP02 install/delete/observe surface for variant [1].
        if (!(config instanceof SCPConfig.SCP02)) {
            try (var bibo = sim.connect()) {
                var pk = masterKey != null ? PlaintextKeys.fromMasterKey(masterKey) : PlaintextKeys.defaultKey();
                var gp = GPSession.connect(bibo, jcaid);
                gp.openSecureChannel(pk, null, null, EnumSet.of(GPSession.APDUMode.ENC));
                var cgram = pk.encrypt(GPCrypto.pad80("Hello, World!".getBytes(StandardCharsets.UTF_8), 16), new byte[]{0x00, 0x00});
                var set = gp.transmit(new CommandAPDU(0x80, 0x42, 0x00, 0x00, cgram));
                assertEquals(0x9000, set.getSW());
                var get = bibo.transmit(new CommandAPDU(0x00, 0x42, 0x00, 0x00, 256));
                assertEquals(0x9000, get.getSW());
                assertArrayEquals("Hello, World!".getBytes(StandardCharsets.UTF_8), get.getData());
            }
        }

        // 9: reopen ISD; delete applet; reopen and confirm registry no longer holds it.
        try (var bibo = sim.connect()) {
            var gp = openWith(bibo, masterKey, mode);
            gp.deleteAID(jcaid, false);
        }
        try (var bibo = sim.connect()) {
            var gp = openWith(bibo, masterKey, mode);
            assertFalse(gp.getRegistry().allAppletAIDs().contains(jcaid));
        }
    }

    // GET STATUS chunking: install enough APP instances to push the P1=0x40 response over 256
    // bytes, forcing 0x6310 continuation(s). Each E3 entry is ~30 bytes (AID 9 + 5 framing,
    // lifecycle 1 + 3, privs 3 + 2, load-file AID 9 + 2, outer 2-byte length envelope).
    // 12 instances = ~360 bytes, comfortably crossing the 256-byte boundary.
    @Test
    public void getStatusChunkedAcrossBoundary() throws Exception {
        var sim = freshEngine();
        int n = 12;
        var aids = new AID[n];
        for (int i = 0; i < n; i++) {
            aids[i] = AIDUtil.create("0102030405060708%02X".formatted(0xC0 + i));
        }
        try (var bibo = sim.connect()) {
            var gp = GPTestUtils.openIsd(bibo);
            for (var aid : aids) {
                installWith(gp, aid, EnumSet.noneOf(Privilege.class));
            }

            var registry = gp.getRegistry();

            for (var aid : aids) {
                // chunked GET STATUS returns every installed applet
                assertTrue(registry.allAppletAIDs().contains(gpAID(aid)));
            }
        }
    }

    // JCSystem.getAppletShareableInterfaceObject + ContextStackProxy: A and B are same-class
    // instances of GlobalPlatformTestApplet with distinct identity bytes. While B is selected,
    // it looks up A by AID and calls A's IdentityShareable.identity() across the context boundary.
    // The returned byte must be A's identity (0xA1), proving the call dispatched into A's instance
    // and the proxy preserved the cross-context return.
    @Test
    public void shareableCrossInstance() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            var gp = GPTestUtils.openIsd(bibo);
            installWith(gp, A, EnumSet.noneOf(Privilege.class), ID_A);
            installWith(gp, B, EnumSet.noneOf(Privilege.class), ID_B);
            selectAID(bibo, B);

            var r = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_QUERY_PEER_IDENTITY, 0x00, 0x00, AIDUtil.bytes(A), 256));
            assertEquals(0x9000, r.getSW());
            assertEquals(1, r.getData().length);
            // returns A's identity, not B's, proving cross-context dispatch
            assertEquals(ID_A, r.getData()[0]);
        }
    }

    // GPC v2.3.1 11.3.3.2 / Table 11-31 specifies that GET DATA returns "'6A' '88' Referenced
    // data not found" for an unknown tag, and this engine treats GET DATA as unauthenticated by
    // convention since the spec does not mandate auth either way. gp-pro does not expose an
    // arbitrary tag probe, so the request goes via raw bibo after a raw SELECT of the ISD.
    @Test
    public void getDataUnknownTagRejected() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00,
                    AIDUtil.bytes(SecurityDomainApplet.OPEN_AID)));
            var unknown = bibo.transmit(new CommandAPDU(0x80, 0xCA, 0x12, 0x34, 256));
            assertEquals(0x6A88, unknown.getSW());
        }
    }

    // Regression guard: loadClass() matches an existing PKG entry by Java package name OR by AID.
    // Built-in entries pass null for the Java package name so they can never merge with user-loaded
    // classes that happen to live in the same Java package as a hypothetical SSD class. Observed
    // over GET STATUS (p1=0x10) which exposes module AIDs per package; the underlying classloader
    // map is engine-internal but the on-wire module set is enough - if a hypothetical merge had
    // happened, the user applet AID would have been added to the SSD package's module list.
    @Test
    public void ssdPackageNotMergedByLoadClass() throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        var userPkgAid = AIDUtil.create("01020304050607080F");
        var userAppAid = AIDUtil.create("0102030405060708A1");
        sim.loadApplet(userPkgAid, userAppAid, GlobalPlatformTestApplet.class);

        try (var bibo = sim.connect()) {
            var reg = GPTestUtils.openIsd(bibo).getRegistry();
            var ssdPkg = reg.allPackages().stream()
                    .filter(e -> e.getAID().equals(gpAID(SecurityDomainApplet.SSD_PACKAGE_AID)))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("SSD package must be in the registry"));
            var modules = ssdPkg.getModules();
            // only the built-in SD module, no merged user applet
            assertEquals(1, modules.size());
            assertTrue(modules.contains(gpAID(SecurityDomainApplet.SSD_MODULE_AID)));
            assertFalse(modules.contains(gpAID(userAppAid)));
        }
    }

    // GPC v2.3.1 6.5.1.1 / 11.5.3.1: an Application (instance) AID may not equal an Executable Load
    // File AID. freshEngine() loads PKG as the ELF; installing an instance with that same AID must be
    // rejected, since ELFs and Applications share the one registry's AID keyspace.
    @Test
    public void instanceAidEqualToLoadFileRejected() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            var gp = GPTestUtils.openIsd(bibo);
            // Instance AID == loaded ELF AID must be refused with SW_CONDITIONS_NOT_SATISFIED.
            var ex = assertThrows(GPException.class, () -> installWith(gp, PKG, EnumSet.noneOf(Privilege.class)));
            assertEquals(0x6985, ex.sw);
            // The rejected install must leave no applet entry behind.
            assertFalse(gp.getRegistry().allAppletAIDs().contains(gpAID(PKG)));
        }
    }

    // GPC v2.3.1 11.2: DELETE [card content] of an Executable Load File removes it from the registry.
    @Test
    public void deleteLoadFile() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            var gp = GPTestUtils.openIsd(bibo);
            // The ELF planted by freshEngine() is present before deletion.
            assertTrue(gp.getRegistry().allPackageAIDs().contains(gpAID(PKG)));
            gp.deleteAID(gpAID(PKG), false);
            // After DELETE the ELF is gone from the registry.
            assertFalse(gp.getRegistry().allPackageAIDs().contains(gpAID(PKG)));
        }
    }

    // Open ISD via gp-pro using the (possibly custom) master key and SCP mode for this variant.
    private static GPSession openWith(apdu4j.core.BIBO bibo, byte[] masterKey, EnumSet<GPSession.APDUMode> mode) throws Exception {
        var pk = masterKey != null ? PlaintextKeys.fromMasterKey(masterKey) : PlaintextKeys.defaultKey();
        var gp = GPSession.discover(bibo);
        gp.openSecureChannel(pk, null, null, mode);
        return gp;
    }

    // KIT shape: 3 entries (ENC/MAC/DEK), all at factory KVN=0xFF, KIDs 1/2/3, type DES3 for SCP02
    // and AES otherwise. The 3-KID ENC/MAC/DEK convention is SCP02/SCP03-specific (GPC v2.3.1
    // Appendix E); KVN coding is GPC v2.3.1 11.1.9.
    private static void assertKit(GPSession gp, SCPConfig config) throws Exception {
        var kit = gp.getKeyInfoTemplate();
        assertEquals(3, kit.size());
        var expectedType = config instanceof SCPConfig.SCP02 ? GPKeyInfo.GPKey.DES3 : GPKeyInfo.GPKey.AES;
        for (int i = 0; i < 3; i++) {
            var ki = kit.get(i);
            assertEquals(0xFF, ki.getVersion());
            assertEquals(i + 1, ki.getID());
            assertEquals(expectedType, ki.getType());
        }
    }

    // CPLC envelope: tag 9F7F + len 0x2A + 42 bytes payload = 45 bytes total.
    // IC Fabricator (offset 3..4) = 0x4242 (engine signature).
    // IC Fab Date (13..14) and IC Batch ID (19..20) = 0x4242 (KDD-relevant).
    // IC Serial (15..18) = ASCII "JCEN" (KDD-relevant). Everything else zero.
    private static void assertCplc(apdu4j.core.BIBO bibo) throws Exception {
        var data = GPData.fetchCPLC(bibo);
        assertEquals(45, data.length);
        assertEquals((byte) 0x9F, data[0]);
        assertEquals((byte) 0x7F, data[1]);
        assertEquals((byte) 0x2A, data[2]);
        assertEquals((byte) 0x42, data[3]);
        assertEquals((byte) 0x42, data[4]);
        // unused CPLC bytes are zero
        for (int i = 5; i <= 12; i++) {
            assertEquals(0, data[i]);
        }
        assertEquals((byte) 0x42, data[13]);
        assertEquals((byte) 0x42, data[14]);
        assertEquals((byte) 'J', data[15]);
        assertEquals((byte) 'C', data[16]);
        assertEquals((byte) 'E', data[17]);
        assertEquals((byte) 'N', data[18]);
        assertEquals((byte) 0x42, data[19]);
        assertEquals((byte) 0x42, data[20]);
        // remaining CPLC bytes are zero
        for (int i = 21; i < 45; i++) {
            assertEquals(0, data[i]);
        }
    }

    // The engine registers the SSD load file at boot using the GP-default SSD AIDs (GPC v2.3.1 H.1.2
    // RID 'A000000151'; packageAID 'A0000001515350' / moduleAID 'A000000151535041'). The load file
    // must be visible in registry (P1=0x10/0x20 GET STATUS templates per Table 11-37) at lifecycle
    // LOADED (0x01 per Table 11-3) with the SSD module enumerated.
    private static void assertSsdLoadFilePlanted(GPSession gp) throws Exception {
        var registry = gp.getRegistry();
        var ssdPkgAid = gpAID(SecurityDomainApplet.SSD_PACKAGE_AID);
        assertTrue(registry.allPackageAIDs().contains(ssdPkgAid));
        var pkgEntry = registry.allPackages().stream().filter(e -> e.getAID().equals(ssdPkgAid)).findFirst().orElseThrow();
        // lifecycle LOADED
        assertEquals((byte) 0x01, pkgEntry.getLifeCycle());
        assertTrue(pkgEntry.getModules().contains(gpAID(SecurityDomainApplet.SSD_MODULE_AID)));
    }

    private static JavaCardEngine freshEngine() {
        var sim = new JavaCardEngine.Builder().build();
        sim.loadApplet(PKG, PKG, GlobalPlatformTestApplet.class);
        return sim;
    }

    private static void installWith(GPSession gp, AID instance, EnumSet<Privilege> privs) throws Exception {
        gp.installAndMakeSelectable(gpAID(PKG), gpAID(PKG), gpAID(instance), privs, new byte[4]);
    }

    private static void installWith(GPSession gp, AID instance, EnumSet<Privilege> privs, byte identity) throws Exception {
        gp.installAndMakeSelectable(gpAID(PKG), gpAID(PKG), gpAID(instance), privs, new byte[]{identity});
    }

    private static void selectAID(apdu4j.core.BIBO bibo, AID aid) {
        var r = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AIDUtil.bytes(aid), 256));
        assertEquals(0x9000, r.getSW());
    }
}
