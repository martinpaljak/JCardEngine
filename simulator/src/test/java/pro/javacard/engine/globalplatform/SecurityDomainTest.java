// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.bouncycastle.util.encoders.Hex;
import org.testng.annotations.Test;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.engine.testapplets.GlobalPlatformTestApplet;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPRegistry;
import pro.javacard.gp.GPRegistryEntry;
import pro.javacard.gp.GPRegistryEntry.ISDLifeCycle;
import pro.javacard.gp.GPRegistryEntry.Kind;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.keys.PlaintextKeys;
import pro.javacard.tlv.TLV;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.stream.StreamSupport;

import static org.testng.Assert.*;
import static pro.javacard.engine.globalplatform.GPTestUtils.MasterKeys;
import static pro.javacard.engine.globalplatform.GPTestUtils.addKvn;
import static pro.javacard.engine.globalplatform.GPTestUtils.gpAID;
import static pro.javacard.engine.globalplatform.GPTestUtils.installSSD;
import static pro.javacard.engine.globalplatform.GPTestUtils.openIsd;
import static pro.javacard.engine.globalplatform.GPTestUtils.openSdMac;

// Single end-to-end narrative covering the SSD lifecycle: install via ISD, parent walk-up key
// resolution (GPC v2.3.1 7.1 SD key separation; chain via 6.5.1.6 Associated SD AID), per-applet
// SELECT FCI build-out (GPC v2.3.1 11.9.3.1 / Table 11-82), the SELECTABLE -> PERSONALIZED
// transition triggered by the SSD owner's first PUT KEY (GPC v2.3.1 5.3.2.3 / Table 11-5),
// key-isolation cut-off after personalization, and extradition (GPC v2.3.1 11.5.2.3.4 /
// Table 11-45; semantics in 9.4.1) including post-extradition key resolution along the new chain.
// Replaces SSDInstallTest, SSDPersonalizationTest, AssociationTest, ExtraditionTest. Wire-only
// observability via gp-pro's GPRegistry; no engine-internal casts.
public class SecurityDomainTest {

    private static final AID PKG = AIDUtil.create("01020304050607080F");
    private static final AID APP = AIDUtil.create("0102030405060708A1");
    private static final AID SSD = GPTestUtils.test_aid("5344");
    private static final AID GHOST = AIDUtil.create("DEADBEEFCAFEBABE99");
    private static final AID NEW_ISD = AIDUtil.create("A0000001515555");

    @Test
    public void ssdLifecycleAndKeyResolution() throws Exception {
        var sim = new JavaCardEngine.Builder().build();

        // 1. Install SSD via ISD; reopen the ISD and inspect the registry. The SSD must show
        // up under allDomains() with Kind.SSD, parented at the ISD AID, in SELECTABLE (0x07)
        // per GPC v2.3.1 Table 11-5, and carry the SecurityDomain privilege.
        try (var bibo = sim.connect()) {
            installSSD(openIsd(bibo), SSD);
        }
        try (var bibo = sim.connect()) {
            var registry = openIsd(bibo).getRegistry();
            var ssdEntry = findDomain(registry, SSD);
            assertEquals(ssdEntry.getType(), Kind.SSD);
            // SSD parent is the issuing ISD (GPC v2.3.1 6.5.1.6)
            assertEquals(ssdEntry.getDomain(), Optional.of(gpAID(SecurityDomainApplet.OPEN_AID)));
            // SELECTABLE per GPC v2.3.1 Table 11-5
            assertEquals(ssdEntry.getLifeCycle(), (byte) 0x07);
            assertTrue(ssdEntry.getPrivileges().contains(Privilege.SecurityDomain));
            // install() insists on TrustedPath too
            assertTrue(ssdEntry.getPrivileges().contains(Privilege.TrustedPath));
        }

        // 2. Bare SELECT [by AID] of the SSD must return 9000 with an FCI whose 84 (Application
        // AID) tag carries the SSD's own AID - proves fci(AID) is built per-applet rather than
        // echoing the hardcoded ISD AID. This is the ONE place a raw CommandAPDU is justified;
        // gp-pro does not surface the FCI bytes from its own SELECT path.
        try (var bibo = sim.connect()) {
            var ssdBytes = AIDUtil.bytes(SSD);
            var r = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, ssdBytes, 256));
            assertEquals(r.getSW(), 0x9000);
            var fci = r.getData();
            // FCI template tag (GPC v2.3.1 11.9.3.1 / Table 11-82)
            assertEquals(fci[0], (byte) 0x6F);
            // Application AID tag inside FCI
            assertEquals(fci[2], (byte) 0x84);
            int aidLen = fci[3] & 0xFF;
            byte[] aidInFci = new byte[aidLen];
            System.arraycopy(fci, 4, aidInFci, 0, aidLen);
            // FCI carries the selected SSD's own AID, not the ISD AID
            assertEquals(aidInFci, ssdBytes);
        }

        // 3. Open SCP to the freshly-installed SSD with the bootstrap default key. The SSD owns
        // no keys yet, so key resolution walks up to the ISD's KVN=0xFF (GPC v2.3.1 7.1).
        try (var bibo = sim.connect()) {
            var gp = GPSession.connect(bibo, gpAID(SSD));
            gp.openSecureChannel(PlaintextKeys.defaultKey(), null, null, EnumSet.of(GPSession.APDUMode.MAC));
        }

        // 4. Regression: the ISD's own SCP path must still work after an SSD has been installed.
        try (var bibo = sim.connect()) {
            openIsd(bibo);
        }

        // 5. SSD owner's first PUT KEY: reopen SSD via parent walk-up and add KVN=0x01 with A.
        try (var bibo = sim.connect()) {
            var gp = GPSession.connect(bibo, gpAID(SSD));
            gp.openSecureChannel(PlaintextKeys.defaultKey(), null, null, EnumSet.of(GPSession.APDUMode.MAC));
            addKvn(gp, 0x01, MasterKeys.A);
        }

        // 6. Wire-observable lifecycle transition: SSD must now be PERSONALIZED (0x0F) per
        // GPC v2.3.1 5.3.2.3 / Table 11-5 (first PUT KEY of an owner key).
        try (var bibo = sim.connect()) {
            var registry = openIsd(bibo).getRegistry();
            assertEquals(findDomain(registry, SSD).getLifeCycle(), (byte) 0x0F);
        }

        // 7. Owner master at KVN=0x01 authenticates the SSD directly (no parent walk).
        try (var bibo = sim.connect()) {
            openSdMac(bibo, SSD, MasterKeys.A, 0x01);
        }

        // 8. Parent's bootstrap key must NO LONGER reach the SSD - the walk-up stops at the
        // SSD's own non-empty keystore. This is what makes the PERSONALIZED transition
        // meaningful (key isolation, GPC v2.3.1 7.1).
        try (var bibo = sim.connect()) {
            var gp = GPSession.connect(bibo, gpAID(SSD));
            assertThrows(GPException.class,
                    () -> gp.openSecureChannel(PlaintextKeys.defaultKey(), null, null, EnumSet.of(GPSession.APDUMode.MAC)));
        }

        // 9. ISD's own keys are untouched: PUT KEY on the SSD must not have affected the ISD.
        try (var bibo = sim.connect()) {
            openIsd(bibo);
        }

        // 10. Install an APP under the ISD. Its associated SD must be the ISD per GPC v2.3.1
        // 6.5.1.6: "All Executable Load Files and Applications, including Security Domains, are
        // associated with a Security Domain, whose AID is given in the registry."
        sim.loadApplet(PKG, APP, GlobalPlatformTestApplet.class);
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            gp.installAndMakeSelectable(gpAID(PKG), gpAID(APP), gpAID(APP), EnumSet.noneOf(Privilege.class), new byte[0]);
        }
        try (var bibo = sim.connect()) {
            var registry = openIsd(bibo).getRegistry();
            assertEquals(findEntry(registry, APP).getDomain(), Optional.of(gpAID(SecurityDomainApplet.OPEN_AID)));
        }

        // 11. INSTALL [for extradition] of APP onto the SSD. After extradition, the registry's
        // associated SD for APP must flip to the SSD AID per GPC v2.3.1 11.5.2.3.4 / Table 11-45.
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            gp.extradite(gpAID(APP), gpAID(SSD));
        }
        try (var bibo = sim.connect()) {
            var registry = openIsd(bibo).getRegistry();
            assertEquals(findEntry(registry, APP).getDomain(), Optional.of(gpAID(SSD)));
        }

        // 12. Post-extradition key resolution: SCP to APP with the SSD owner's master at KVN=0x01
        // succeeds (key resolution walks APP -> SSD), while the ISD's bootstrap key fails
        // (no longer reachable from APP's chain post-extradition; GPC v2.3.1 7.1).
        try (var bibo = sim.connect()) {
            openSdMac(bibo, APP, MasterKeys.A, 0x01);
        }
        try (var bibo = sim.connect()) {
            var gp = GPSession.connect(bibo, gpAID(APP));
            assertThrows(GPException.class,
                    () -> gp.openSecureChannel(PlaintextKeys.defaultKey(), null, null, EnumSet.of(GPSession.APDUMode.MAC)));
        }
    }

    // Self-extradition (target == new SD) would self-parent a non-ISD entity, so the SD applet
    // rejects it as engine policy with SW_WRONG_DATA (6A80) drawn from GPC v2.3.1 11.5.3.2 /
    // Table 11-55.
    @Test
    public void selfExtraditionRejected() throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            installSSD(gp, SSD);
            var ex = expectThrows(GPException.class, () -> gp.extradite(gpAID(SSD), gpAID(SSD)));
            assertEquals(ex.sw, 0x6A80);
        }
    }

    // Extradition of an unknown target AID, or onto an unknown SD AID, must yield
    // SW_REFERENCED_DATA_NOT_FOUND (6A88) per GPC v2.3.1 11.5.3.2 / Table 11-55.
    @Test
    public void unknownTargetAndUnknownSdRejected() throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        sim.loadApplet(PKG, APP, GlobalPlatformTestApplet.class);
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            installSSD(gp, SSD);
            var unknownTarget = expectThrows(GPException.class, () -> gp.extradite(gpAID(GHOST), gpAID(SSD)));
            assertEquals(unknownTarget.sw, 0x6A88);

            gp.installAndMakeSelectable(gpAID(PKG), gpAID(APP), gpAID(APP), EnumSet.noneOf(Privilege.class), new byte[0]);
            var unknownSd = expectThrows(GPException.class, () -> gp.extradite(gpAID(APP), gpAID(GHOST)));
            assertEquals(unknownSd.sw, 0x6A88);
        }
    }

    // Extradition requires AuthorizedManagement on the executing SD (GPC v2.3.1 9.4.1 + 6.6.1).
    // Scenario A: SSD without AM, authenticated via parent walk-up, must be denied with 6982.
    // Scenario B: SSD WITH AM on a fresh sim must succeed and the registry must flip.
    @Test
    public void extraditionRequiresAuthorizedManagement() throws Exception {
        // Scenario A: SSD without AM.
        var simA = new JavaCardEngine.Builder().build();
        simA.loadApplet(PKG, APP, GlobalPlatformTestApplet.class);
        try (var bibo = simA.connect()) {
            var gp = openIsd(bibo);
            installSSD(gp, SSD);
            gp.installAndMakeSelectable(gpAID(PKG), gpAID(APP), gpAID(APP), EnumSet.noneOf(Privilege.class), new byte[0]);
        }
        try (var bibo = simA.connect()) {
            var gp = openSdMac(bibo, SSD, MasterKeys.BOOTSTRAP, 0);
            var ex = expectThrows(GPException.class, () -> gp.extradite(gpAID(APP), gpAID(SSD)));
            assertEquals(ex.sw, 0x6982);
        }

        // Scenario B: SSD WITH AM privilege - extradition must succeed and the registry flips.
        var simB = new JavaCardEngine.Builder().build();
        simB.loadApplet(PKG, APP, GlobalPlatformTestApplet.class);
        try (var bibo = simB.connect()) {
            var gp = openIsd(bibo);
            installSSD(gp, SSD, EnumSet.of(Privilege.AuthorizedManagement));
            gp.installAndMakeSelectable(gpAID(PKG), gpAID(APP), gpAID(APP), EnumSet.noneOf(Privilege.class), new byte[0]);
        }
        try (var bibo = simB.connect()) {
            var gp = openSdMac(bibo, SSD, MasterKeys.BOOTSTRAP, 0);
            gp.extradite(gpAID(APP), gpAID(SSD));
        }
        try (var bibo = simB.connect()) {
            var registry = openIsd(bibo).getRegistry();
            assertEquals(findEntry(registry, APP).getDomain(), Optional.of(gpAID(SSD)));
        }
    }

    // GPC v2.3.1 11.9.3.2 / Table 11-83: SELECT may return warning SW '62' '83' "Card Life Cycle
    // State is CARD_LOCKED" when the Security Domain with the Final Application privilege is being
    // selected, with the FCI still returned alongside the warning so the host can recognise the
    // selected SD before reacting to the locked state.
    @Test
    public void finalApplicationSelectWarningWhenCardLocked() throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            installSSD(gp, SSD, EnumSet.of(Privilege.FinalApplication));
            gp.setCardStatus(ISDLifeCycle.INITIALIZED);
            gp.setCardStatus(ISDLifeCycle.SECURED);
            gp.setCardStatus(ISDLifeCycle.CARD_LOCKED);
        }
        try (var bibo = sim.connect()) {
            var ssdBytes = AIDUtil.bytes(SSD);
            var r = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, ssdBytes, 256));
            // warning SW per GPC v2.3.1 11.9.3.2 / Table 11-83
            assertEquals(r.getSW(), 0x6283);
            var fci = r.getData();
            // warning response still carries the FCI template
            assertEquals(fci[0], (byte) 0x6F);
            assertEquals(fci[2], (byte) 0x84);
            int aidLen = fci[3] & 0xFF;
            byte[] aidInFci = new byte[aidLen];
            System.arraycopy(fci, 4, aidInFci, 0, aidLen);
            assertEquals(aidInFci, ssdBytes);
        }
    }

    // Negative: when the SSD lacks the FinalApplication privilege, SELECT under CARD_LOCKED must
    // return a clean SW 9000 with FCI; the warning is gated specifically on the privilege per
    // Table 11-83. This guards against the warning leaking to ordinary SDs.
    @Test
    public void nonFinalApplicationSelectIsCleanWhenCardLocked() throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            installSSD(gp, SSD);
            gp.setCardStatus(ISDLifeCycle.INITIALIZED);
            gp.setCardStatus(ISDLifeCycle.SECURED);
            gp.setCardStatus(ISDLifeCycle.CARD_LOCKED);
        }
        try (var bibo = sim.connect()) {
            var r = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AIDUtil.bytes(SSD), 256));
            // warning is privilege-gated (Table 11-83): non-final SD selects cleanly
            assertEquals(r.getSW(), 0x9000);
        }
    }

    // Negative: SSD with FinalApplication but card NOT in CARD_LOCKED must return SW 9000, since
    // the warning is gated on both the privilege AND the locked lifecycle per Table 11-83.
    @Test
    public void finalApplicationSelectIsCleanWhenCardNotLocked() throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        try (var bibo = sim.connect()) {
            installSSD(openIsd(bibo), SSD, EnumSet.of(Privilege.FinalApplication));
        }
        try (var bibo = sim.connect()) {
            var r = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AIDUtil.bytes(SSD), 256));
            // warning needs both privilege AND CARD_LOCKED (Table 11-83); not locked -> clean
            assertEquals(r.getSW(), 0x9000);
        }
    }

    // STORE DATA tag 4F renames the ISD (GPC v2.3.1 11.11.2.3: 4F is a settable Issuer Security
    // Domain data object); the engine re-keys the ISD in the registry. gp-pro's --rename-isd drives
    // this via GPSession.renameISD(). The new AID only takes over after a reconnect (real cards: a
    // card reset clears the live selection), modelled here by closing a reset-on-close session.
    @Test
    public void renameISDViaStoreData() throws Exception {
        var sim = new JavaCardEngine.Builder().build();

        try (var bibo = sim.connect("*", true)) {
            var gp = openIsd(bibo);
            // First try a collision: an already-registered AID (here the ISD's own current AID) is
            // refused with 6A80, registry untouched. Then rename to a free AID on the same session.
            var ex = expectThrows(GPException.class, () -> gp.renameISD(gpAID(SecurityDomainApplet.OPEN_AID)));
            assertEquals(ex.sw, 0x6A80);
            gp.renameISD(gpAID(NEW_ISD));
        }

        try (var bibo = sim.connect()) {
            var gp = GPSession.connect(bibo, gpAID(NEW_ISD));
            gp.openSecureChannel(PlaintextKeys.defaultKey(), null, null, EnumSet.of(GPSession.APDUMode.MAC));
            var registry = gp.getRegistry();
            // ISD now registered under the new AID, with the original bootstrap keys intact
            assertEquals(registry.getISD().orElseThrow().getAID(), gpAID(NEW_ISD));
            // the original ISD AID is gone from the registry
            assertTrue(registry.getDomain(gpAID(SecurityDomainApplet.OPEN_AID)).isEmpty());
        }
    }

    // GPC v2.3.1 11.11.2 STORE DATA [GP data] on the ISD. The CPLC perso (9F66) and pre-perso (9F67)
    // slices are read-modify-written into the card's read-only 9F7F CPLC at fixed offsets; the full
    // CPLC, an unknown data object, a wrong-length slice and the encrypted P1 format are each
    // rejected with 6A80. A slice split across two blocks proves multi-block accumulation. Driven
    // through gp-pro's GPSession.storeData (last-block bit and block numbering managed by gp-pro).
    @Test
    public void storeDataCplcSlicesAndRejects() throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        byte[] perso = Hex.decode("1122334455667788");
        byte[] preperso = Hex.decode("99AABBCCDDEEFF00");

        try (var bibo = sim.connect("*", true)) {
            var gp = openIsd(bibo);
            gp.storeData(TLV.of(0x9F66, perso).encode(), 0x00);
            gp.storeData(TLV.of(0x9F67, preperso).encode(), 0x00);

            // 9F7F is read-only; an unknown tag and a wrong-length slice all reject.
            assertEquals(expectThrows(GPException.class, () -> gp.storeData(TLV.of(0x9F7F, new byte[8]).encode(), 0x00)).sw, 0x6A80);
            assertEquals(expectThrows(GPException.class, () -> gp.storeData(TLV.of(0x9F50, new byte[2]).encode(), 0x00)).sw, 0x6A80);
            assertEquals(expectThrows(GPException.class, () -> gp.storeData(TLV.of(0x9F66, new byte[7]).encode(), 0x00)).sw, 0x6A80);

            // Encrypted STORE DATA format (P1 bits 0x18) is unsupported. gp-pro's storeData refuses
            // to build it, so wrap a hand-built last-block command (P1=0x98) through the channel.
            var enc = gp.transmit(new CommandAPDU(0x80, 0xE2, 0x98, 0x00, TLV.of(0x9F66, perso).encode()));
            assertEquals(enc.getSW(), 0x6A80);
        }

        // Multi-block: a single 9F67 slice split into two STORE DATA blocks is accumulated then committed.
        try (var bibo = sim.connect("*", true)) {
            var gp = openIsd(bibo);
            byte[] t = TLV.of(0x9F67, preperso).encode();
            gp.storeData(List.of(Arrays.copyOfRange(t, 0, 4), Arrays.copyOfRange(t, 4, t.length)), 0x00);
        }

        // GET DATA 9F7F (public, unauthenticated): both slices landed at offsets 26 and 34.
        try (var bibo = sim.connect()) {
            var r = bibo.transmit(new CommandAPDU(0x80, 0xCA, 0x9F, 0x7F, 256));
            assertEquals(r.getSW(), 0x9000);
            byte[] cplc = TLV.parse(r.getData()).find(0x9F7F).orElseThrow().value();
            assertEquals(Arrays.copyOfRange(cplc, 26, 34), preperso);
            assertEquals(Arrays.copyOfRange(cplc, 34, 42), perso);
        }
    }

    // Look up a domain entry by AID from gp-pro's registry; fails the test if missing.
    private static GPRegistryEntry findDomain(GPRegistry registry, AID aid) {
        var found = registry.getDomain(gpAID(aid));
        assertTrue(found.isPresent());
        return found.get();
    }

    // Look up any entry (applet or domain) by AID from gp-pro's registry; fails if missing.
    // GPRegistry exposes byModule()/getDomain() but no general AID lookup, so iterate.
    private static GPRegistryEntry findEntry(GPRegistry registry, AID aid) {
        var gpaid = gpAID(aid);
        var found = StreamSupport.stream(registry.spliterator(), false)
                .filter(e -> e.getAID().equals(gpaid))
                .findFirst();
        assertTrue(found.isPresent());
        return found.get();
    }
}
