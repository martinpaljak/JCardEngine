// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.junit.jupiter.api.Test;
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

import java.util.EnumSet;
import java.util.Optional;
import java.util.stream.StreamSupport;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
    private static final AID SSD = AIDUtil.create("D2330000007753534402");
    private static final AID GHOST = AIDUtil.create("DEADBEEFCAFEBABE99");

    @Test
    void ssdLifecycleAndKeyResolution() throws Exception {
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
            assertEquals(Kind.SSD, ssdEntry.getType(), "freshly-installed SSD must be classified Kind.SSD");
            assertEquals(Optional.of(gpAID(SecurityDomainApplet.OPEN_AID)), ssdEntry.getDomain(), "SSD parent must be the issuing ISD (GPC v2.3.1 6.5.1.6 Associated Security Domain AID)");
            assertEquals((byte) 0x07, ssdEntry.getLifeCycle(), "newly-installed SSD must start at SELECTABLE (0x07) per GPC v2.3.1 Table 11-5");
            assertTrue(ssdEntry.getPrivileges().contains(Privilege.SecurityDomain), "SSD entry must carry the SecurityDomain privilege (GPC v2.3.1 Table 6-1)");
        }

        // 2. Bare SELECT [by AID] of the SSD must return 9000 with an FCI whose 84 (Application
        // AID) tag carries the SSD's own AID — proves fci(AID) is built per-applet rather than
        // echoing the hardcoded ISD AID. This is the ONE place a raw CommandAPDU is justified;
        // gp-pro does not surface the FCI bytes from its own SELECT path.
        try (var bibo = sim.connect()) {
            var ssdBytes = AIDUtil.bytes(SSD);
            var r = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, ssdBytes, 256));
            assertEquals(0x9000, r.getSW(), "SELECT of installed SSD must succeed (GPC v2.3.1 11.9)");
            var fci = r.getData();
            assertEquals((byte) 0x6F, fci[0], "FCI template tag (GPC v2.3.1 11.9.3.1 / Table 11-82)");
            assertEquals((byte) 0x84, fci[2], "Application AID tag inside FCI (GPC v2.3.1 11.9.3.1 / Table 11-82)");
            int aidLen = fci[3] & 0xFF;
            byte[] aidInFci = new byte[aidLen];
            System.arraycopy(fci, 4, aidInFci, 0, aidLen);
            assertArrayEquals(ssdBytes, aidInFci, "SELECT FCI must carry the selected SSD's own AID, not the ISD AID (GPC v2.3.1 11.9.3.1 / Table 11-82)");
        }

        // 3. Open SCP to the freshly-installed SSD with the bootstrap default key. The SSD owns
        // no keys yet, so resolveMasterKey walks up to the ISD's KVN=0xFF (GPC v2.3.1 7.1).
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
            assertEquals((byte) 0x0F, findDomain(registry, SSD).getLifeCycle(), "after owner PUT KEY, SSD must transition SELECTABLE -> PERSONALIZED (GPC v2.3.1 5.3.2.3)");
        }

        // 7. Owner master at KVN=0x01 authenticates the SSD directly (no parent walk).
        try (var bibo = sim.connect()) {
            openSdMac(bibo, SSD, MasterKeys.A, 0x01);
        }

        // 8. Parent's bootstrap key must NO LONGER reach the SSD — the walk-up stops at the
        // SSD's own non-empty keystore. This is what makes the PERSONALIZED transition
        // meaningful (key isolation, GPC v2.3.1 7.1).
        try (var bibo = sim.connect()) {
            var gp = GPSession.connect(bibo, gpAID(SSD));
            assertThrows(GPException.class,
                    () -> gp.openSecureChannel(PlaintextKeys.defaultKey(), null, null, EnumSet.of(GPSession.APDUMode.MAC)),
                    "after PUT KEY, parent's default keys must not authenticate the SSD (GPC v2.3.1 7.1 key isolation)");
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
            assertEquals(Optional.of(gpAID(SecurityDomainApplet.OPEN_AID)), findEntry(registry, APP).getDomain(), "fresh APP must be associated with the issuing ISD (GPC v2.3.1 6.5.1.6)");
        }

        // 11. INSTALL [for extradition] of APP onto the SSD. After extradition, the registry's
        // associated SD for APP must flip to the SSD AID per GPC v2.3.1 11.5.2.3.4 / Table 11-45.
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            gp.extradite(gpAID(APP), gpAID(SSD));
        }
        try (var bibo = sim.connect()) {
            var registry = openIsd(bibo).getRegistry();
            assertEquals(Optional.of(gpAID(SSD)), findEntry(registry, APP).getDomain(), "after extradition, APP's associated SD must be the new SSD (GPC v2.3.1 9.4.1 Content Extradition)");
        }

        // 12. Post-extradition key resolution: SCP to APP with the SSD owner's master at KVN=0x01
        // succeeds (resolveMasterKey walks APP -> SSD), while the ISD's bootstrap key fails
        // (no longer reachable from APP's chain post-extradition; GPC v2.3.1 7.1).
        try (var bibo = sim.connect()) {
            openSdMac(bibo, APP, MasterKeys.A, 0x01);
        }
        try (var bibo = sim.connect()) {
            var gp = GPSession.connect(bibo, gpAID(APP));
            assertThrows(GPException.class,
                    () -> gp.openSecureChannel(PlaintextKeys.defaultKey(), null, null, EnumSet.of(GPSession.APDUMode.MAC)),
                    "after extradition, ISD's bootstrap key must no longer reach APP via the SSD chain (GPC v2.3.1 7.1)");
        }
    }

    // Self-extradition (target == new SD) would self-parent a non-ISD entity, so the SD applet
    // rejects it as engine policy with SW_WRONG_DATA (6A80) drawn from GPC v2.3.1 11.5.3.2 /
    // Table 11-55.
    @Test
    void selfExtraditionRejected() throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            installSSD(gp, SSD);
            var ex = assertThrows(GPException.class, () -> gp.extradite(gpAID(SSD), gpAID(SSD)));
            assertEquals(0x6A80, ex.sw, "self-extradition must be rejected with SW_WRONG_DATA (6A80) per GPC v2.3.1 11.5.3.2 / Table 11-55");
        }
    }

    // Extradition of an unknown target AID, or onto an unknown SD AID, must yield
    // SW_REFERENCED_DATA_NOT_FOUND (6A88) per GPC v2.3.1 11.5.3.2 / Table 11-55.
    @Test
    void unknownTargetAndUnknownSdRejected() throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        sim.loadApplet(PKG, APP, GlobalPlatformTestApplet.class);
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            installSSD(gp, SSD);
            var unknownTarget = assertThrows(GPException.class, () -> gp.extradite(gpAID(GHOST), gpAID(SSD)));
            assertEquals(0x6A88, unknownTarget.sw, "unknown extradition target must be rejected with SW_REFERENCED_DATA_NOT_FOUND (6A88) per GPC v2.3.1 11.5.3.2 / Table 11-55");

            gp.installAndMakeSelectable(gpAID(PKG), gpAID(APP), gpAID(APP), EnumSet.noneOf(Privilege.class), new byte[0]);
            var unknownSd = assertThrows(GPException.class, () -> gp.extradite(gpAID(APP), gpAID(GHOST)));
            assertEquals(0x6A88, unknownSd.sw, "unknown new SD must be rejected with SW_REFERENCED_DATA_NOT_FOUND (6A88) per GPC v2.3.1 11.5.3.2 / Table 11-55");
        }
    }

    // Extradition requires AuthorizedManagement on the executing SD (GPC v2.3.1 9.4.1 + 6.6.1).
    // Scenario A: SSD without AM, authenticated via parent walk-up, must be denied with 6982.
    // Scenario B: SSD WITH AM on a fresh sim must succeed and the registry must flip.
    @Test
    void extraditionRequiresAuthorizedManagement() throws Exception {
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
            var ex = assertThrows(GPException.class, () -> gp.extradite(gpAID(APP), gpAID(SSD)));
            assertEquals(0x6982, ex.sw, "extradition by an SSD lacking AM must yield SW_SECURITY_STATUS_NOT_SATISFIED (6982) since AM is required per GPC v2.3.1 9.4.1 and 6.6.1");
        }

        // Scenario B: SSD WITH AM privilege — extradition must succeed and the registry flips.
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
            assertEquals(Optional.of(gpAID(SSD)), findEntry(registry, APP).getDomain(), "AM-privileged SSD must be allowed to extradite APP onto itself (GPC v2.3.1 9.4.1 / 11.5.2.3.4)");
        }
    }

    // GPC v2.3.1 11.9.3.2 / Table 11-83: SELECT may return warning SW '62' '83' "Card Life Cycle
    // State is CARD_LOCKED" when the Security Domain with the Final Application privilege is being
    // selected, with the FCI still returned alongside the warning so the host can recognise the
    // selected SD before reacting to the locked state.
    @Test
    void finalApplicationSelectWarningWhenCardLocked() throws Exception {
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
            assertEquals(0x6283, r.getSW(), "Final Application SD selected while CARD_LOCKED must yield warning SW 6283 (GPC v2.3.1 11.9.3.2 / Table 11-83)");
            var fci = r.getData();
            assertEquals((byte) 0x6F, fci[0], "warning response must still carry the FCI template (GPC v2.3.1 11.9.3.1 / Table 11-82)");
            assertEquals((byte) 0x84, fci[2], "FCI must contain the Application AID tag");
            int aidLen = fci[3] & 0xFF;
            byte[] aidInFci = new byte[aidLen];
            System.arraycopy(fci, 4, aidInFci, 0, aidLen);
            assertArrayEquals(ssdBytes, aidInFci, "FCI AID must be the selected SSD's own AID even under the warning condition");
        }
    }

    // Negative: when the SSD lacks the FinalApplication privilege, SELECT under CARD_LOCKED must
    // return a clean SW 9000 with FCI; the warning is gated specifically on the privilege per
    // Table 11-83. This guards against the warning leaking to ordinary SDs.
    @Test
    void nonFinalApplicationSelectIsCleanWhenCardLocked() throws Exception {
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
            assertEquals(0x9000, r.getSW(), "SSD without FinalApplication must still SELECT cleanly even when CARD_LOCKED, since the Table 11-83 warning is privilege-gated");
        }
    }

    // Negative: SSD with FinalApplication but card NOT in CARD_LOCKED must return SW 9000, since
    // the warning is gated on both the privilege AND the locked lifecycle per Table 11-83.
    @Test
    void finalApplicationSelectIsCleanWhenCardNotLocked() throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        try (var bibo = sim.connect()) {
            installSSD(openIsd(bibo), SSD, EnumSet.of(Privilege.FinalApplication));
        }
        try (var bibo = sim.connect()) {
            var r = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AIDUtil.bytes(SSD), 256));
            assertEquals(0x9000, r.getSW(), "Final Application SD selected outside CARD_LOCKED must return SW 9000 since the Table 11-83 warning requires both conditions");
        }
    }

    // Look up a domain entry by AID from gp-pro's registry; fails the test if missing.
    private static GPRegistryEntry findDomain(GPRegistry registry, AID aid) {
        var found = registry.getDomain(gpAID(aid));
        assertTrue(found.isPresent(), "domain entry must be present in registry: " + aid);
        return found.get();
    }

    // Look up any entry (applet or domain) by AID from gp-pro's registry; fails if missing.
    // GPRegistry exposes byModule()/getDomain() but no general AID lookup, so iterate.
    private static GPRegistryEntry findEntry(GPRegistry registry, AID aid) {
        var gpaid = gpAID(aid);
        var found = StreamSupport.stream(registry.spliterator(), false)
                .filter(e -> e.getAID().equals(gpaid))
                .findFirst();
        assertTrue(found.isPresent(), "registry entry must be present: " + aid);
        return found.get();
    }
}
