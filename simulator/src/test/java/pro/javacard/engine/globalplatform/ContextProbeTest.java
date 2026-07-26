// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.testng.annotations.Test;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.engine.testapplets.ContextProbeApplet;
import pro.javacard.gp.GPRegistryEntry.Privilege;

import java.util.EnumSet;

import static org.testng.Assert.*;
import static pro.javacard.engine.globalplatform.GPTestUtils.gpAID;
import static pro.javacard.engine.globalplatform.GPTestUtils.openIsd;

public class ContextProbeTest {

    private static final AID PKG_AID = AIDUtil.create("D233000000774354582D3031");
    private static final AID APPLET_AID = AIDUtil.create("D233000000774354582D303101");

    @Test
    public void selectionContextDuringInstallAndPersonalization() throws Exception {
        var r = drive();

        // Every pre-register OPEN call returned rather than throwing.
        assertTrue(r.preGP().ok(), "pre-register OPEN services: " + r.preGP());

        // GP API 1.8 GPSystem.getRegistryEntry: an entry comes back only "if it was found in the
        // GlobalPlatform Registry", and register() is what puts it there.
        assertEquals(r.preEntry(), ContextProber.ABSENT);
        // GP API 1.8 GPSystem.getCVM and getSecureChannel resolve through the caller's own registry
        // entry, which an applet that has not registered does not have.
        assertEquals(r.preCVM(), ContextProber.ABSENT);
        assertEquals(r.preSecureChannel(), ContextProber.ABSENT);
        // No entry means no recorded Life Cycle State to report.
        assertEquals(r.preState(), 0);
        // After register() the Application is in the registry and reads its own entry.
        assertEquals(r.postEntry(), ContextProber.PRESENT);

        // JCRE 3.2 11.2: the new applet is the currently selected applet during install(), so a
        // CLEAR_ON_DESELECT allocation in the constructor is accepted.
        assertTrue(r.ctorCod().ok(), "ctor COD allocation: " + r.ctorCod());
        assertTrue(r.codIsTransient());

        // JCRE 3.2 11.2: after register() the instance AID is the applet's own.
        assertEquals(r.installAid(), ContextProber.AID_INSTANCE);

        // JCRE 3.2 11.2: CLEAR_ON_DESELECT objects created during install() belong to the new
        // applet's selection context, so the allocation is accepted there too.
        assertTrue(r.installCod().ok(), "install COD allocation: " + r.installCod());

        // JCRE 3.2 6.1.5: creating a CLEAR_ON_DESELECT object outside the selected applet's
        // context throws SystemException ILLEGAL_TRANSIENT.
        assertTrue(r.persoMake().system(ContextProber.ILLEGAL_TRANSIENT), "perso COD allocation: " + r.persoMake());

        // GPC v2.3.1 7.3.2: processData() runs in the target applet's own context.
        assertEquals(r.persoAID(), AIDUtil.bytes(APPLET_AID));

        // The invoking Security Domain is the previous context. The ISD is an applet instance
        // here, so its AID is returned instead of the null that a JCRE-context caller gives.
        assertEquals(r.persoPrevAID(), AIDUtil.bytes(SecurityDomainApplet.OPEN_AID));
    }

    // Disabled until the firewall lands: no object carries an owning context yet, so the access half
    // of the rule has no enforcement point.
    @Test(enabled = false)
    public void codAccessOutsideSelectedContextIsNotDeniedYet() throws Exception {
        var r = drive();

        // JCRE 3.2 6.1.5 and 6.2.8.2: the Security Domain is the currently selected applet during
        // forwarded STORE DATA, so the target's own CLEAR_ON_DESELECT array is denied on read,
        // on write, and as an arrayCopy source.
        assertTrue(r.persoRead().security(), "perso COD read: " + r.persoRead());
        assertTrue(r.persoWrite().security(), "perso COD write: " + r.persoWrite());
        assertTrue(r.persoCopy().security(), "perso COD arrayCopy: " + r.persoCopy());
    }

    // Installs the applet, personalizes it indirectly through the ISD and reads back what it recorded.
    private static ContextProber.Results drive() throws Exception {
        var sim = JavaCardEngine.create();
        sim.loadApplet(PKG_AID, APPLET_AID, ContextProbeApplet.class);

        // INSTALL [for install and make selectable] (GPC v2.3.1 11.5.2.3.2) runs the install-time probes.
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            gp.installAndMakeSelectable(gpAID(PKG_AID), gpAID(APPLET_AID), gpAID(APPLET_AID), EnumSet.noneOf(Privilege.class), new byte[0]);
        }

        // INSTALL [for personalization] + STORE DATA (GPC v2.3.1 11.5.2.3.6, 11.11) run the
        // processData() probes, with the Security Domain still the selected applet.
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            gp.installForPersonalization(gpAID(APPLET_AID));
            gp.storeData(new byte[]{0x01, 0x02, 0x03, 0x04}, 0x00);
        }

        try (var bibo = sim.connect()) {
            var prober = new ContextProber(bibo);
            prober.select(AIDUtil.bytes(APPLET_AID));
            var r = prober.read();
            System.out.println(r.table());

            // Baseline: the same COD operations with the applet selected are all allowed (JCRE 3.2 6.1.5).
            var baseline = prober.touch();
            assertTrue(baseline.ok(), "baseline: " + baseline);

            // Every processData() probe was attempted and returned; no probe killed the applet.
            assertEquals(r.step(), ContextProber.STEP_PERSO_DONE);
            return r;
        }
    }
}
