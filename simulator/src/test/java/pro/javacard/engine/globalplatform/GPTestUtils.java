// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import apdu4j.core.BIBO;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.bouncycastle.util.encoders.Hex;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.keys.PlaintextKeys;

import java.util.EnumSet;

// Cross-cutting fixtures for GlobalPlatformEngine engine tests. Keeps the FQN/JC <-> gp-pro AID
// conversion in one place and folds repeated SCP / SSD-install boilerplate into single calls.
final class GPTestUtils {
    private GPTestUtils() {
    }

    // Master keys reused across PutKey/DeleteKey/NewestKeyset/SSDPersonalization tests. A/B/C
    // are arbitrary distinct values; BOOTSTRAP is the platform default the ISD ships with.
    static final class MasterKeys {
        public static final byte[] BOOTSTRAP = PlaintextKeys.DEFAULT_KEY();
        public static final byte[] A = Hex.decode("0102030405060708090A0B0C0D0E0F10");
        public static final byte[] B = Hex.decode("AABBCCDDEEFF00112233445566778899");
        public static final byte[] C = Hex.decode("FFEEDDCCBBAA99887766554433221100");

        private MasterKeys() {
        }
    }

    // Convert javacard.framework.AID (used everywhere in the engine + tests) to gp-pro's
    // pro.javacard.capfile.AID, which is what GPSession's API takes. The only place that
    // crosses the type boundary; tests stay on the JC framework AID type.
    static pro.javacard.capfile.AID gpAID(AID aid) {
        return new pro.javacard.capfile.AID(AIDUtil.bytes(aid));
    }

    // Open an ISD SCP session with the bootstrap default key and MAC-only APDU wrapping.
    static GPSession openIsd(BIBO bibo) throws Exception {
        return openIsd(bibo, EnumSet.of(GPSession.APDUMode.MAC));
    }

    // Open an ISD SCP session with the bootstrap default key and a caller-chosen APDU mode.
    static GPSession openIsd(BIBO bibo, EnumSet<GPSession.APDUMode> mode) throws Exception {
        var gp = GPSession.discover(bibo);
        gp.openSecureChannel(PlaintextKeys.defaultKey(), null, null, mode);
        return gp;
    }

    // INSTALL [for install and make selectable] of an SSD instance via the platform-built-in
    // SSD load file (mirrors GPTool's --domain). Adds Privilege.SecurityDomain and any extras.
    static void installSSD(GPSession gp, AID instance, EnumSet<Privilege> extras) throws Exception {
        var privs = EnumSet.of(Privilege.SecurityDomain);
        privs.addAll(extras);
        gp.installAndMakeSelectable(gpAID(SecurityDomainApplet.SSD_PACKAGE_AID), gpAID(SecurityDomainApplet.SSD_MODULE_AID), gpAID(instance), privs, new byte[0]);
    }

    static void installSSD(GPSession gp, AID instance) throws Exception {
        installSSD(gp, instance, EnumSet.noneOf(Privilege.class));
    }

    // PUT KEY add (P1=00): introduces a new keyset under kvn from the given master.
    static void addKvn(GPSession gp, int kvn, byte[] master) throws Exception {
        var keys = PlaintextKeys.fromMasterKey(master);
        keys.setVersion(kvn);
        gp.putKeys(keys, false);
    }

    // PUT KEY replace (P1=kvn): replaces an existing keyset at kvn with the given master.
    static void replaceKvn(GPSession gp, int kvn, byte[] master) throws Exception {
        var keys = PlaintextKeys.fromMasterKey(master);
        keys.setVersion(kvn);
        gp.putKeys(keys, true);
    }

    // SELECT an SD by AID and open SCP with the given master/kvn. kvn==0 leaves the keyset
    // unset so INITIALIZE UPDATE goes out with P1=00 (newest-keyset selection on the card).
    static GPSession openSdAt(BIBO bibo, AID aid, byte[] master, int kvn, EnumSet<GPSession.APDUMode> mode) throws Exception {
        var gp = GPSession.connect(bibo, gpAID(aid));
        var keys = PlaintextKeys.fromMasterKey(master);
        if (kvn != 0) {
            keys.setVersion(kvn);
        }
        gp.openSecureChannel(keys, null, null, mode);
        return gp;
    }

    // MAC-mode convenience over openSdAt; matches what most SD-targeted tests need.
    static GPSession openSdMac(BIBO bibo, AID aid, byte[] master, int kvn) throws Exception {
        return openSdAt(bibo, aid, master, kvn, EnumSet.of(GPSession.APDUMode.MAC));
    }
}
