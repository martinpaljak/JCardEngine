// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.bouncycastle.util.encoders.Hex;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
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
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Map;

import static org.testng.Assert.*;
import static pro.javacard.engine.globalplatform.GPTestUtils.gpAID;

// Install/execute/observe over the SCP variants, plus GET STATUS chunking, shareable cross-instance,
// GET DATA unknown tags and load-file registration.
public class InstallExecuteAndObserveTest {

    private static final AID PKG = AIDUtil.create("01020304050607080F");
    private static final AID A = AIDUtil.create("0102030405060708A1");
    private static final AID B = AIDUtil.create("0102030405060708B2");

    private static final byte ID_A = (byte) 0xA1;
    private static final byte ID_B = (byte) 0xB2;

    @DataProvider(name = "scpConfigs")
    public static Object[][] scpConfigs() {
        byte[] custom128 = Hex.decode("000102030405060708090A0B0C0D0E0F");
        byte[] custom256 = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        return new Object[][] {
                {"SCP02-MAC", new SCPConfig.SCP02(), null, EnumSet.of(GPSession.APDUMode.MAC)},
                {"SCP02-ENC", new SCPConfig.SCP02(), null, EnumSet.of(GPSession.APDUMode.ENC)},
                {"SCP03-MAC", new SCPConfig.SCP03(), null, EnumSet.of(GPSession.APDUMode.MAC)},
                {"SCP03-S16-ENC", new SCPConfig.SCP03(true), null, EnumSet.of(GPSession.APDUMode.ENC)},
                {"Custom128-SCP03-ENC", new SCPConfig.SCP03(custom128), custom128, EnumSet.of(GPSession.APDUMode.ENC)},
                {"Custom256-SCP03-ENC", new SCPConfig.SCP03(custom256), custom256, EnumSet.of(GPSession.APDUMode.ENC)}
        };
    }

    @Test(dataProvider = "scpConfigs")
    public void installExecuteObserve(String name, SCPConfig config, byte[] masterKey,
                                      EnumSet<GPSession.APDUMode> mode) throws Exception {
        var sim = new JavaCardEngine.Builder().withSCP(config).build();
        // ELF and instance AIDs must differ (GPC v2.3.1 6.5.1.1); instance = ELF + instance byte.
        var pkgAID = AIDUtil.create("010203040506070809");
        var appletAID = AIDUtil.create("01020304050607080901");
        var jcaid = gpAID(appletAID);
        sim.loadApplet(pkgAID, appletAID, GlobalPlatformTestApplet.class);

        // Open ISD, inspect KIT. Own session: gp.getKeyInfoTemplate() takes the SCP-wrapped GET DATA
        // path when a session is open, and that session is not reused for follow-up SCP-wrapped
        // commands on the same connection.
        try (var bibo = sim.connect()) {
            // EXTERNAL AUTHENTICATE rejected before any INITIALIZE UPDATE: C-DECRYPTION without C-MAC
            // is an unattainable level (6A86); a valid level with no session keys yet is 6985. The
            // payload is the per-variant EXT AUTH length so the length check passes to the session
            // check. A failed EXT AUTH leaves the channel clean for the positive open below.
            byte[] auth = new byte[config instanceof SCPConfig.SCP03 scp03 && scp03.s16() ? 32 : 16];
            assertEquals(bibo.transmit(new CommandAPDU(0x84, 0x82, 0x02, 0x00, auth)).getSW(), 0x6A86);
            assertEquals(bibo.transmit(new CommandAPDU(0x84, 0x82, 0x01, 0x00, auth)).getSW(), 0x6985);

            var gp = openWith(bibo, masterKey, mode);
            assertKit(gp, config);
        }

        // Fresh session: CPLC via raw bibo, registry visibility for the planted SSD load file.
        try (var bibo = sim.connect()) {
            var gp = openWith(bibo, masterKey, mode);
            assertCplc(bibo);
            assertSsdLoadFilePlanted(gp);
        }

        try (var bibo = sim.connect()) {
            var gp = openWith(bibo, masterKey, mode);
            gp.installAndMakeSelectable(gpAID(pkgAID), jcaid, jcaid, EnumSet.noneOf(Privilege.class), new byte[]{(byte) 0x55});
        }

        // Reopen ISD; registry sees applet + package + ISD.
        try (var bibo = sim.connect()) {
            var gp = openWith(bibo, masterKey, mode);
            var registry = gp.getRegistry();
            assertTrue(registry.allAppletAIDs().contains(jcaid));
            assertTrue(registry.allPackageAIDs().contains(gpAID(pkgAID)));
            assertTrue(registry.getISD().isPresent());

            // SELECT applet; round-trip install-param byte via INS_GET_IDENTITY.
            var sel = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AIDUtil.bytes(appletAID), 256));
            assertEquals(sel.getSW(), 0x9000);
            var ident = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_GET_IDENTITY, 0x00, 0x00, 256));
            assertEquals(ident.getSW(), 0x9000);
            assertEquals(ident.getData().length, 1);
            // install-param byte round-trips
            assertEquals(ident.getData()[0], (byte) 0x55);
        }

        // Reopen SCP to applet AID with ENC mode; SCP-encrypted INS 0x42 cgram round-trip.
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
                assertEquals(set.getSW(), 0x9000);
                var get = bibo.transmit(new CommandAPDU(0x00, 0x42, 0x00, 0x00, 256));
                assertEquals(get.getSW(), 0x9000);
                assertEquals(get.getData(), "Hello, World!".getBytes(StandardCharsets.UTF_8));
            }
        }

        // Reopen ISD; delete applet; reopen and confirm registry no longer holds it.
        try (var bibo = sim.connect()) {
            var gp = openWith(bibo, masterKey, mode);
            gp.deleteAID(jcaid, false);
        }
        try (var bibo = sim.connect()) {
            var gp = openWith(bibo, masterKey, mode);
            assertFalse(gp.getRegistry().allAppletAIDs().contains(jcaid));
        }
    }

    @Test
    public void getStatusChunkedAcrossBoundary() throws Exception {
        var sim = freshEngine();
        // Each E3 entry is ~30 bytes (AID 9 + 5 framing, lifecycle 1 + 3, privs 3 + 2, load-file AID
        // 9 + 2, outer 2-byte length envelope), so 12 instances are ~360 bytes: enough to push the
        // P1=0x40 response past 256 bytes and force 0x6310 continuation(s).
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

    @Test
    public void shareableCrossInstance() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            var gp = GPTestUtils.openIsd(bibo);
            installWith(gp, A, EnumSet.noneOf(Privilege.class), ID_A);
            installWith(gp, B, EnumSet.noneOf(Privilege.class), ID_B);
            selectAID(bibo, B);

            // B, selected, fetches A's SIO by AID and calls identity() on it
            var r = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_QUERY_PEER_IDENTITY, 0x00, 0x00, AIDUtil.bytes(A), 256));
            assertEquals(r.getSW(), 0x9000);
            assertEquals(r.getData().length, 1);
            // the SIO belongs to A, so identity() returns A's byte, JCRE 3.2 6.2.7.1
            assertEquals(r.getData()[0], ID_A);

            // What A recorded when B fetched its SIO above (Simulator.getSharedObject)
            selectAID(bibo, A);
            var sioA = sioAids(bibo);
            // owner is the server itself, JCRE 3.2 6.2.7.2 step 4
            assertEquals(sioA.getKey(), AIDUtil.bytes(A));
            // clientAID is the caller, JCRE 3.2 6.2.7.2 step 3
            assertEquals(sioA.getValue(), AIDUtil.bytes(B));

            // What B recorded during its own install, when EVENT_SELECTABLE reached it through
            // getSystemSharedObject with the ISD on the context stack
            selectAID(bibo, B);
            var sioB = sioAids(bibo);
            // owner is the server itself, JCRE 3.2 6.2.7.2 step 4
            assertEquals(sioB.getKey(), AIDUtil.bytes(B));
            // platform fetch has no client
            assertEquals(sioB.getValue().length, 0);
        }
    }

    @Test
    public void getDataUnknownTagRejected() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            // gp-pro exposes no arbitrary tag probe, so the request goes via raw bibo after a raw SELECT.
            // The engine treats GET DATA as unauthenticated (the spec mandates auth neither way).
            bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00,
                    AIDUtil.bytes(SecurityDomainApplet.OPEN_AID)));
            var unknown = bibo.transmit(new CommandAPDU(0x80, 0xCA, 0x12, 0x34, 256));
            // GPC v2.3.1 11.3.3.2 Table 11-31: an unknown tag returns "'6A' '88' Referenced data not found"
            assertEquals(unknown.getSW(), 0x6A88);
        }
    }

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
            // loadClass() matches a package entry by Java package name or by AID; built-in entries carry
            // a null package name, so a user class in the same Java package cannot join the SSD module
            // list reported by GET STATUS (p1=0x10).
            var modules = ssdPkg.getModules();
            // only the built-in SD module, no merged user applet
            assertEquals(modules.size(), 1);
            assertTrue(modules.contains(gpAID(SecurityDomainApplet.SSD_MODULE_AID)));
            assertFalse(modules.contains(gpAID(userAppAid)));
        }
    }

    @Test
    public void instanceAidEqualToLoadFileRejected() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            var gp = GPTestUtils.openIsd(bibo);
            // GPC v2.3.1 6.5.1.1: an instance AID equal to the loaded ELF AID (both share the one registry
            // AID keyspace) is refused with SW_CONDITIONS_NOT_SATISFIED.
            var ex = expectThrows(GPException.class, () -> installWith(gp, PKG, EnumSet.noneOf(Privilege.class)));
            assertEquals(ex.sw, 0x6985);
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

        // DELETE negatives (GPC v2.3.1 11.2): unknown AID -> 6A88, the ISD cannot be deleted -> 6985,
        // and a DELETE whose data field carries no '4F' AID tag -> 6A80.
        try (var bibo = sim.connect()) {
            var gp = GPTestUtils.openIsd(bibo);
            assertEquals(expectThrows(GPException.class, () -> gp.deleteAID(gpAID(A), false)).sw, 0x6A88);
            assertEquals(expectThrows(GPException.class, () -> gp.deleteAID(gpAID(SecurityDomainApplet.OPEN_AID), false)).sw, 0x6985);
            var noAid = gp.transmit(new CommandAPDU(0x80, 0xE4, 0x00, 0x00, new byte[]{0x4E, 0x01, 0x00}));
            assertEquals(noAid.getSW(), 0x6A80);
        }
    }

    // Open ISD via gp-pro using the (possibly custom) master key and SCP mode for this variant.
    private static GPSession openWith(BIBO bibo, byte[] masterKey, EnumSet<GPSession.APDUMode> mode) throws Exception {
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
        assertEquals(kit.size(), 3);
        var expectedType = config instanceof SCPConfig.SCP02 ? GPKeyInfo.GPKey.DES3 : GPKeyInfo.GPKey.AES;
        for (int i = 0; i < 3; i++) {
            var ki = kit.get(i);
            assertEquals(ki.getVersion(), 0xFF);
            assertEquals(ki.getID(), i + 1);
            assertEquals(ki.getType(), expectedType);
        }
    }

    // CPLC envelope: tag 9F7F + len 0x2A + 42 bytes payload = 45 bytes total.
    // IC Fabricator (offset 3..4) = 0x4242 (engine signature).
    // IC Fab Date (13..14) and IC Batch ID (19..20) = 0x4242 (KDD-relevant).
    // IC Serial (15..18) = ASCII "JCEN" (KDD-relevant). Everything else zero.
    private static void assertCplc(BIBO bibo) throws Exception {
        var data = GPData.fetchCPLC(bibo);
        assertEquals(data.length, 45);
        assertEquals(data[0], (byte) 0x9F);
        assertEquals(data[1], (byte) 0x7F);
        assertEquals(data[2], (byte) 0x2A);
        assertEquals(data[3], (byte) 0x42);
        assertEquals(data[4], (byte) 0x42);
        // unused CPLC bytes are zero
        for (int i = 5; i <= 12; i++) {
            assertEquals(data[i], 0);
        }
        assertEquals(data[13], (byte) 0x42);
        assertEquals(data[14], (byte) 0x42);
        assertEquals(data[15], (byte) 'J');
        assertEquals(data[16], (byte) 'C');
        assertEquals(data[17], (byte) 'E');
        assertEquals(data[18], (byte) 'N');
        assertEquals(data[19], (byte) 0x42);
        assertEquals(data[20], (byte) 0x42);
        // remaining CPLC bytes are zero
        for (int i = 21; i < 45; i++) {
            assertEquals(data[i], 0);
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
        assertEquals(pkgEntry.getLifeCycle(), (byte) 0x01);
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

    private static void selectAID(BIBO bibo, AID aid) {
        var r = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AIDUtil.bytes(aid), 256));
        assertEquals(r.getSW(), 0x9000);
    }

    // INS_SIO_AIDS response is [len][own AID][len][clientAID], returned as (own, client).
    private static Map.Entry<byte[], byte[]> sioAids(BIBO bibo) {
        var r = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SIO_AIDS, 0x00, 0x00, 256));
        assertEquals(r.getSW(), 0x9000);
        var data = r.getData();
        int ownLen = data[0] & 0xFF;
        int clientLen = data[1 + ownLen] & 0xFF;
        var own = Arrays.copyOfRange(data, 1, 1 + ownLen);
        var client = Arrays.copyOfRange(data, 2 + ownLen, 2 + ownLen + clientLen);
        return Map.entry(own, client);
    }
}
