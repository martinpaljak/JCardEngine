// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import org.globalplatform.CVM;
import org.globalplatform.GPSystem;
import org.testng.annotations.Test;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.engine.testapplets.GlobalPlatformTestApplet;
import pro.javacard.gp.GPRegistryEntry.ISDLifeCycle;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPSession;

import java.util.EnumSet;

import static org.testng.Assert.*;
import static pro.javacard.engine.globalplatform.GPTestUtils.gpAID;
import static pro.javacard.engine.globalplatform.GPTestUtils.openIsd;

// Card and application life cycle state machines, the GPSystem and registry-entry JC-API surface, CardReset auto-select and the Global PIN CVM.
public class CardLifecycleAndPrivilegesTest {

    private static final AID PKG = AIDUtil.create("01020304050607080F");
    private static final AID A = AIDUtil.create("0102030405060708A1");
    private static final AID B = AIDUtil.create("0102030405060708B2");

    private static final byte ID_A = (byte) 0xA1;
    private static final byte ID_B = (byte) 0xB2;

    private static final byte INS_SET_STATUS = (byte) 0xF0;
    private static final byte P1_CARD_LCS = (byte) 0x80;

    @Test
    public void cardLifecycleStateMachine() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);

            // GPC v2.3.1 5.1.1.1: virgin card boots in OP_READY.
            assertEquals(gp.getRegistry().getISD().get().getLifeCycle(), (byte) 0x01);

            // GPC v2.3.1 5.1.1.2: from OP_READY, only INITIALIZED is reachable. Direct skips and self-loop rejected.
            assertSetStatusRejected(gp, 0x0F); // OP_READY -> SECURED skip
            assertSetStatusRejected(gp, 0x7F); // OP_READY -> CARD_LOCKED skip
            assertSetStatusRejected(gp, 0x01); // OP_READY -> OP_READY no-op
            // lifecycle unchanged after rejected transitions
            assertEquals(gp.getRegistry().getISD().get().getLifeCycle(), (byte) 0x01);

            // GPC v2.3.1 Table 11-86: P1 values other than 0x80 (card) and 0x40 (application) are unsupported.
            var p1Bad = gp.transmit(new CommandAPDU(0x80, INS_SET_STATUS, 0x60, 0x07));
            assertEquals(p1Bad.getSW(), 0x6A81);

            // GPC v2.3.1 5.1.1.2: OP_READY -> INITIALIZED.
            gp.setCardStatus(ISDLifeCycle.INITIALIZED);
            assertEquals(gp.getRegistry().getISD().get().getLifeCycle(), (byte) 0x07);

            // GPC v2.3.1 5.1.1.2: INITIALIZED is irreversible.
            assertSetStatusRejected(gp, 0x01); // INITIALIZED -> OP_READY (irreversible)

            // GPC v2.3.1 5.1.1.3: INITIALIZED -> SECURED.
            gp.setCardStatus(ISDLifeCycle.SECURED);
            assertEquals(gp.getRegistry().getISD().get().getLifeCycle(), (byte) 0x0F);

            // GPC v2.3.1 5.1.1.4: post-issuance lock/unlock is reversible (CardLock privilege held by ISD).
            gp.setCardStatus(ISDLifeCycle.CARD_LOCKED);
            assertEquals(gp.getRegistry().getISD().get().getLifeCycle(), (byte) 0x7F);
            gp.setCardStatus(ISDLifeCycle.SECURED);
            assertEquals(gp.getRegistry().getISD().get().getLifeCycle(), (byte) 0x0F);

            // GPC v2.3.1 5.1.1.5: TERMINATED is reachable from any non-terminal state (CardTerminate privilege).
            gp.setCardStatus(ISDLifeCycle.TERMINATED);

            // GPC v2.3.1 5.1.1.5: TERMINATED is irreversible - no transition out, including self-loop.
            assertSetStatusRejected(gp, 0x0F); // TERMINATED -> SECURED
            assertSetStatusRejected(gp, 0x07); // TERMINATED -> INITIALIZED
            assertSetStatusRejected(gp, 0x01); // TERMINATED -> OP_READY
            assertSetStatusRejected(gp, 0xFF); // TERMINATED -> TERMINATED no-op
        }
    }

    @Test
    public void gpSystemCardStateApi() throws Exception {
        // From SECURED: lockCard gated by CardLock; ISD stays SECURED on rejection.
        try (var bibo = freshEngine().connect()) {
            var gp = openIsd(bibo);
            advanceToSecured(gp);
            installWith(gp, A, EnumSet.noneOf(Privilege.class));   // no CardLock
            installWith(gp, B, EnumSet.of(Privilege.CardLock));    // with CardLock

            selectAID(bibo, A);
            // GPC v2.3.1 5.1.1.4: an Application needs Card Lock to initiate the transition to CARD_LOCKED
            assertGpSystemReturns(bibo, GlobalPlatformTestApplet.INS_LOCK_CARD, false);
            // ISD stays SECURED after rejected lockCard
            assertEquals(openIsd(bibo).getRegistry().getISD().get().getLifeCycle(), (byte) 0x0F);

            selectAID(bibo, B);
            // lockCard with CardLock from SECURED
            assertGpSystemReturns(bibo, GlobalPlatformTestApplet.INS_LOCK_CARD, true);
            // GPSystem.getCardState (JC-API view) MUST track the actual ISD lifecycle byte
            // observable via GET STATUS - same source of truth, different surface.
            var rState = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_GET_CARD_STATE, 0x00, 0x00, 256));
            assertEquals(rState.getSW(), 0x9000);
            // getCardState reports CARD_LOCKED after lockCard
            assertEquals(rState.getData()[0], (byte) 0x7F);
        }

        // Right privilege, wrong source state: lockCard from OP_READY rejected by GPC v2.3.1 5.1.1.4.
        try (var bibo = freshEngine().connect()) {
            var gp = openIsd(bibo);
            installWith(gp, A, EnumSet.of(Privilege.CardLock));    // no advanceToSecured
            selectAID(bibo, A);
            // lockCard from OP_READY (state machine rejects)
            assertGpSystemReturns(bibo, GlobalPlatformTestApplet.INS_LOCK_CARD, false);
        }

        // terminateCard is irreversible, so it comes last on its own card.
        try (var bibo = freshEngine().connect()) {
            var gp = openIsd(bibo);
            advanceToSecured(gp);
            installWith(gp, A, EnumSet.of(Privilege.CardLock));      // not CardTerminate
            installWith(gp, B, EnumSet.of(Privilege.CardTerminate));

            selectAID(bibo, A);
            // GPC v2.3.1 5.1.1.5: Card Lock alone does not authorize the move to TERMINATED
            assertGpSystemReturns(bibo, GlobalPlatformTestApplet.INS_TERMINATE_CARD, false);

            selectAID(bibo, B);
            // terminateCard with CardTerminate
            assertGpSystemReturns(bibo, GlobalPlatformTestApplet.INS_TERMINATE_CARD, true);
        }
    }

    @Test
    public void cardResetTransferAndAutoSelect() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect("*", true)) {
            var gp = openIsd(bibo);
            installWith(gp, A, EnumSet.of(Privilege.CardReset), ID_A);
            installWith(gp, B, EnumSet.of(Privilege.CardReset), ID_B);
        }
        try (var bibo = sim.connect()) {
            var r = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_GET_IDENTITY, 0x00, 0x00, 256));
            // GPC v2.3.1 6.6.2: only one Application holds Card Reset at a time, so installing B takes it from A and B auto-selects on power-up
            assertEquals(r.getSW(), 0x9000);
            assertEquals(r.getData().length, 1);
            assertEquals(r.getData()[0], ID_B);
        }

        try (var bibo = sim.connect("*", true)) {
            var gp = openIsd(bibo);
            gp.deleteAID(gpAID(B), false);
            gp.deleteAID(gpAID(A), false);
        }
        try (var bibo = sim.connect()) {
            var r = bibo.transmit(new CommandAPDU(0x00, 0x07, 0x00, 0x00, 256));
            // GPC v2.3.1 6.6.2: deleting the holder reassigns Card Reset to the ISD, which then auto-selects and answers the unknown INS itself
            assertEquals((short) r.getSW(), ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // JCRE 3.2 4.2.1: a Card Reset holder whose select() refuses leaves nothing selected after power-up.
        var simReject = freshEngine();
        try (var bibo = simReject.connect("*", true)) {
            installWith(openIsd(bibo), A, EnumSet.of(Privilege.CardReset), ID_A, true);
        }
        try (var bibo = simReject.connect()) {
            var r = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_GET_IDENTITY, 0x00, 0x00, 256));
            // JCRE 3.2 4.8: non-SELECT command with no applet selected returns 0x6999
            assertEquals((short) r.getSW(), ISO7816.SW_APPLET_SELECT_FAILED);
        }
    }

    @Test
    public void globalRegistryGate() throws Exception {
        var sim1 = freshEngine();
        try (var bibo = sim1.connect()) {
            var gp = openIsd(bibo);
            installWith(gp, A, EnumSet.noneOf(Privilege.class));
            installWith(gp, B, EnumSet.noneOf(Privilege.class));
            selectAID(bibo, A);

            // GPC v2.3.1 9.6.5: the entity being interrogated is always allowed, so a self-query (null) needs no privilege
            var rNull = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_QUERY_SELF, 0x00, 0x00, 256));
            assertEquals(rNull.getSW(), 0x9000);
            assertEquals(rNull.getData()[0], GPSystem.APPLICATION_SELECTABLE);

            // self-query via own AID
            var rSelf = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_QUERY_AID, 0x00, 0x00, AIDUtil.bytes(A), 256));
            assertEquals(rSelf.getSW(), 0x9000);
            assertEquals(rSelf.getData()[0], GPSystem.APPLICATION_SELECTABLE);

            // GPC v2.3.1 9.6.5: querying another Application without Global Registry is denied
            var rCross = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_QUERY_AID, 0x00, 0x00, AIDUtil.bytes(B), 256));
            assertEquals(rCross.getSW(), 0x6A82);
        }

        var sim2 = freshEngine();
        try (var bibo = sim2.connect()) {
            var gp = openIsd(bibo);
            installWith(gp, A, EnumSet.of(Privilege.GlobalRegistry));
            installWith(gp, B, EnumSet.noneOf(Privilege.class));
            selectAID(bibo, A);

            // GlobalRegistry-privileged cross-applet query succeeds
            var r = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_QUERY_AID, 0x00, 0x00, AIDUtil.bytes(B), 256));
            assertEquals(r.getSW(), 0x9000);
            assertEquals(r.getData()[0], GPSystem.APPLICATION_SELECTABLE);

            // getPrivileges returns the 3-byte bitmap; A holds GlobalRegistry, so it is non-zero.
            var privs = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_QUERY_PRIVS, 0x00, 0x00, 256));
            assertEquals(privs.getSW(), 0x9000);
            assertEquals(privs.getData().length, 3);
            assertTrue((privs.getData()[0] | privs.getData()[1] | privs.getData()[2]) != 0);
        }
    }

    @Test
    public void appletSelfLifecycleTransitions() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            installWith(openIsd(bibo), A, EnumSet.noneOf(Privilege.class));
            selectAID(bibo, A);

            // GP API 1.8 GPSystem.setCardContentState: the applet drives its own life cycle, starting from SELECTABLE (0x07)
            var advance = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS, 0x0F, 0x00, 256));
            assertEquals(advance.getSW(), 0x9000);
            // GPC v2.3.1 5.3.1.5: OPEN accepts app-specific forward transition
            assertEquals(advance.getData()[0], (byte) 0x01);
            assertEquals(advance.getData()[1], (byte) 0x0F);

            // Forward again to a higher app-specific state succeeds since the OPEN does not
            // constrain monotonicity of application-specific transitions.
            var advance2 = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS, 0x1F, 0x00, 256));
            assertEquals(advance2.getData()[0], (byte) 0x01);
            assertEquals(advance2.getData()[1], (byte) 0x1F);

            // Regression to SELECTABLE (0x07) must be refused since INSTALLED -> SELECTABLE is
            // irreversible per GPC v2.3.1 5.3.1.2 and the resulting state would be lower than
            // the current value, which the canonical setState rules also forbid.
            var regress = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS, 0x07, 0x00, 256));
            // GPC v2.3.1 5.3.1.2: regression to SELECTABLE refused (irreversibility)
            assertEquals(regress.getData()[0], (byte) 0x00);
            assertEquals(regress.getData()[1], (byte) 0x1F);

            // Regression to INSTALLED (0x03) must be refused for the same reason.
            var toInstalled = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS, 0x03, 0x00, 256));
            assertEquals(toInstalled.getData()[0], (byte) 0x00);
            assertEquals(toInstalled.getData()[1], (byte) 0x1F);

            // Self-LOCK (b8=1, e.g. 0x83) is accepted per GPC v2.3.1 5.3.1.3 which lists "the
            // Application itself" among entities permitted to set LOCKED. Per the API javadoc,
            // b7..b1 of the new state are ignored on lock so the resulting lifecycle is
            // current OR 0x80 = 0x9F rather than the literal 0x83 passed in.
            var selfLock = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS, 0x83, 0x00, 256));
            // GPC v2.3.1 5.3.1.3: self-LOCK accepted; result is previous OR 0x80
            assertEquals(selfLock.getData()[0], (byte) 0x01);
            assertEquals(selfLock.getData()[1], (byte) 0x9F);

            // After self-lock the applet is no longer in an application-specific state, so any
            // subsequent setCardContentState attempt must fail the API pre-condition (caller
            // must currently be in 0x07..0x7F with low 3 bits set).
            var unlockAttempt = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS, 0x07, 0x00, 256));
            // self-unlock refused: caller no longer in an application-specific state
            assertEquals(unlockAttempt.getData()[0], (byte) 0x00);
            assertEquals(unlockAttempt.getData()[1], (byte) 0x9F);
        }
    }

    @Test
    public void registryEntrySelfStateMatchesContentStateRules() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            installWith(openIsd(bibo), A, EnumSet.noneOf(Privilege.class));
            selectAID(bibo, A);

            // GPC v2.3.1 11.10.2.2: a transition to the CURRENT life cycle state is not legal. The
            // applet sits at SELECTABLE (0x07); setState(0x07) is a no-op transition and is refused.
            var same = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS_VIA_REGISTRY, 0x07, 0x00, 256));
            assertEquals(same.getData()[0], (byte) 0x00);
            assertEquals(same.getData()[1], (byte) 0x07);

            // GPC v2.3.1 5.3.1.3: self-LOCK via setState succeeds; 0x07 OR 0x80 = 0x87
            var lock = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS_VIA_REGISTRY, 0x83, 0x00, 256));
            assertEquals(lock.getData()[0], (byte) 0x01);
            assertEquals(lock.getData()[1], (byte) 0x87);

            // self-unlock via setState refused: applet lacks Global Lock
            var unlock = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS_VIA_REGISTRY, 0x07, 0x00, 256));
            assertEquals(unlock.getData()[0], (byte) 0x00);
            assertEquals(unlock.getData()[1], (byte) 0x87);
        }
    }

    @Test
    public void applicationSetStatusLockUnlock() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            installWith(gp, A, EnumSet.noneOf(Privilege.class));

            // Freshly made-selectable applet starts at SELECTABLE (0x07).
            assertEquals(appLifecycle(gp, A), (byte) 0x07);

            // GPC v2.3.1 11.10 SET STATUS [for application]: P1=0x40, new state in P2, target AID in the data field. An unknown AID gives 0x6A88.
            var unknown = gp.transmit(new CommandAPDU(0x80, INS_SET_STATUS, 0x40, 0x80, AIDUtil.bytes(B)));
            assertEquals(unknown.getSW(), 0x6A88);
        }

        // Lock (P2 b8=1) then unlock (P2 b8=0) the applet via the GPSession helper; the b8 LOCK
        // bit sets/clears the high bit so SELECTABLE 0x07 becomes 0x87 and returns to 0x07.
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            gp.lockUnlockApplet(gpAID(A), true);
            assertEquals(appLifecycle(gp, A), (byte) 0x87);
            // GPC v2.3.1 6.4.2.1.2: a LOCKED application is not selectable by name - the by-name SELECT
            // skips A (no other match), so the ISD stays selected and rejects the ISO-CLA SELECT.
            var locked = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AIDUtil.bytes(A), 256));
            assertNotEquals(locked.getSW(), 0x9000);
        }
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            gp.lockUnlockApplet(gpAID(A), false);
            assertEquals(appLifecycle(gp, A), (byte) 0x07);
        }

        // GPC v2.3.1 11.10.2.2: for another application an SD may only lock/unlock (b8). Any non-lock
        // state push - a regression to INSTALLED (0x03) or an app-specific state (0x1F) - is rejected
        // with 0x6985 and the lifecycle is left at SELECTABLE (0x07).
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            var regress = gp.transmit(new CommandAPDU(0x80, INS_SET_STATUS, 0x40, 0x03, AIDUtil.bytes(A)));
            assertEquals(regress.getSW(), 0x6985);
            assertEquals(appLifecycle(gp, A), (byte) 0x07);

            var arbitrary = gp.transmit(new CommandAPDU(0x80, INS_SET_STATUS, 0x40, 0x1F, AIDUtil.bytes(A)));
            assertEquals(arbitrary.getSW(), 0x6985);
            assertEquals(appLifecycle(gp, A), (byte) 0x07);
        }
    }

    // GPC v2.3.1 8.2 Global PIN (CVM): the org.globalplatform.CVM held by GPSystem.getCVM(CVM_GLOBAL_PIN).
    // update/setTryLimit/blockState/resetAndUnblockState require the caller to hold CVM Management
    // (GPC v2.3.1 Table 6-1); A holds it, B does not. verify drives the retry counter to BLOCKED and
    // back, and a power-up returns a VALIDATED PIN to ACTIVE while BLOCKED survives (GPC v2.3.1 8.2.2.2.1).
    private static final byte[] PIN = {0x12, 0x34};
    private static final byte[] WRONG = {0x00, 0x00};
    private static final byte FORMAT_ASCII = 1; // CVM.FORMAT_ASCII, to drive update's format-mismatch path

    @Test
    public void globalPinCvmLifecycle() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            installWith(gp, A, EnumSet.of(Privilege.CVMManagement)); // CVM Management holder
            installWith(gp, B, EnumSet.noneOf(Privilege.class));      // no CVM Management
        }

        try (var bibo = sim.connect("*", true)) { // reset on close so onCardReset runs before the next phase
            selectAID(bibo, A);

            // Uninitialised: not active; verify and the management ops that require an active CVM fail.
            assertEquals(cvm(bibo, 0x00, 0, null)[0], 0);
            assertEquals(verify(bibo, PIN), CVM.CVM_FAILURE);
            assertEquals(cvm(bibo, 0x05, 0, null)[0], 0); // resetAndUnblock on INACTIVE
            assertEquals(cvm(bibo, 0x04, 0, null)[0], 0); // block on INACTIVE

            // setTryLimit alone does not activate (no value yet); update installs the value and activates.
            assertEquals(cvm(bibo, 0x01, 3, null)[0], 1);
            assertEquals(cvm(bibo, 0x00, 0, null)[0], 0); // still inactive
            assertEquals(cvm(bibo, 0x02, 0, PIN)[0], 1);   // update, FORMAT_HEX
            byte[] st = cvm(bibo, 0x00, 0, null);
            assertEquals(st[0], 1); // active
            assertEquals(st[4], 3); // tries

            // Non-HEX format is rejected by update.
            assertEquals(cvm(bibo, 0x02, FORMAT_ASCII, PIN)[0], 0);

            // Wrong then right: failure decrements the counter, success validates and restores it.
            assertEquals(verify(bibo, WRONG), CVM.CVM_FAILURE);
            assertEquals(cvm(bibo, 0x00, 0, null)[4], 2);
            assertEquals(verify(bibo, PIN), CVM.CVM_SUCCESS);
            assertEquals(cvm(bibo, 0x00, 0, null)[2], 1); // verified
            assertEquals(cvm(bibo, 0x00, 0, null)[4], 3);

            // resetState drops VALIDATED back to ACTIVE without clearing the value.
            assertEquals(cvm(bibo, 0x06, 0, null)[0], 1);
            assertEquals(cvm(bibo, 0x00, 0, null)[2], 0); // not verified

            // Drive the counter to zero -> BLOCKED; a blocked CVM rejects further verification.
            verify(bibo, WRONG);
            verify(bibo, WRONG);
            verify(bibo, WRONG);
            assertEquals(cvm(bibo, 0x00, 0, null)[3], 1); // blocked
            assertEquals(verify(bibo, PIN), CVM.CVM_FAILURE);

            // setTryLimit(0) is rejected; resetAndUnblock clears BLOCKED and restores the counter.
            assertEquals(cvm(bibo, 0x01, 0, null)[0], 0);
            assertEquals(cvm(bibo, 0x05, 0, null)[0], 1);
            assertEquals(cvm(bibo, 0x00, 0, null)[3], 0); // not blocked
            assertEquals(cvm(bibo, 0x00, 0, null)[4], 3);

            // Explicit block then unblock, then validate to set up the power-up reset probe below.
            assertEquals(cvm(bibo, 0x04, 0, null)[0], 1);
            assertEquals(cvm(bibo, 0x05, 0, null)[0], 1);
            assertEquals(verify(bibo, PIN), CVM.CVM_SUCCESS);

            // B lacks CVM Management: every management op fails, regardless of CVM state.
            selectAID(bibo, B);
            assertEquals(cvm(bibo, 0x01, 5, null)[0], 0); // setTryLimit
            assertEquals(cvm(bibo, 0x02, 0, PIN)[0], 0);  // update
            assertEquals(cvm(bibo, 0x04, 0, null)[0], 0); // block
            assertEquals(cvm(bibo, 0x05, 0, null)[0], 0); // resetAndUnblock
        }

        // Power-up returns the VALIDATED PIN to ACTIVE.
        try (var bibo = sim.connect("*", true)) { // reset on close so the block below survives into the next phase
            selectAID(bibo, A);
            assertEquals(cvm(bibo, 0x00, 0, null)[2], 0); // no longer verified
            assertEquals(cvm(bibo, 0x00, 0, null)[0], 1); // still active
            assertEquals(cvm(bibo, 0x04, 0, null)[0], 1); // block it
        }
        // BLOCKED survives a power-up.
        try (var bibo = sim.connect()) {
            selectAID(bibo, A);
            assertEquals(cvm(bibo, 0x00, 0, null)[3], 1); // still blocked
        }
    }

    // Drive the test applet's CVM sub-op (INS_CVM). data == null for the no-argument ops.
    private static byte[] cvm(BIBO bibo, int p1, int p2, byte[] data) {
        var c = data == null
                ? new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_CVM, p1, p2, 256)
                : new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_CVM, p1, p2, data, 256);
        var r = bibo.transmit(c);
        assertEquals(r.getSW(), 0x9000);
        return r.getData();
    }

    // CVM verify sub-op returns [resultHi, resultLo, verified, tries]; first short is the CVM result.
    private static short verify(BIBO bibo, byte[] pin) {
        var d = cvm(bibo, 0x03, 0, pin);
        return (short) ((d[0] << 8) | (d[1] & 0xFF));
    }

    // Read an applet's GET STATUS lifecycle byte via the gp-pro registry (tag 9F70 = getLifeCycle).
    private static byte appLifecycle(GPSession gp, AID aid) throws Exception {
        var gpaid = gpAID(aid);
        return gp.getRegistry().allApplets().stream().filter(e -> e.getAID().equals(gpaid)).findFirst()
                .orElseThrow(() -> new AssertionError("applet not in registry: " + aid)).getLifeCycle();
    }

    @Test
    public void cardResetRequiresMakeSelectable() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            // GPC v2.3.1 Table 11-43: Card Reset requires the same command to make the Application selectable, so install-only (P1=0x04) is rejected
            var r = gp.transmit(installOnlyCommand(A, EnumSet.of(Privilege.CardReset)));
            assertEquals(r.getSW(), 0x6A80);

            // Same install-only command without Card Reset is accepted, proving 0x04 itself works.
            var ok = gp.transmit(installOnlyCommand(B, EnumSet.noneOf(Privilege.class)));
            assertEquals(ok.getSW(), 0x9000);
        }
    }

    // INSTALL [for install] only (P1=0x04): LV pkg | LV applet | LV instance | LV privileges |
    // L install params (C9 00), matching the field layout GPSession.buildInstallData produces for
    // the combined command. Only P1 differs (0x04 install-only vs 0x0C install-and-make-selectable).
    private static CommandAPDU installOnlyCommand(AID instance, EnumSet<Privilege> privs) {
        var bo = new java.io.ByteArrayOutputStream();
        for (var aid : new AID[]{PKG, PKG, instance}) {
            var bytes = AIDUtil.bytes(aid);
            bo.write(bytes.length);
            bo.writeBytes(bytes);
        }
        var privBytes = pro.javacard.gp.data.BitField.encode(privs, 3);
        bo.write(privBytes.length);
        bo.writeBytes(privBytes);
        bo.write(0x02);
        bo.writeBytes(new byte[]{(byte) 0xC9, 0x00});
        bo.write(0x00); // empty install token (6th LV field)
        return new CommandAPDU(0x80, 0xE6, 0x04, 0x00, bo.toByteArray());
    }

    private static JavaCardEngine freshEngine() {
        return freshEngineWith(GlobalPlatformTestApplet.class);
    }

    private static JavaCardEngine freshEngineWith(Class<? extends Applet> applet) {
        var sim = new JavaCardEngine.Builder().build();
        sim.loadApplet(PKG, PKG, applet);
        return sim;
    }

    private static void installWith(GPSession gp, AID instance, EnumSet<Privilege> privs) throws Exception {
        gp.installAndMakeSelectable(gpAID(PKG), gpAID(PKG), gpAID(instance), privs, new byte[4]);
    }

    private static void installWith(GPSession gp, AID instance, EnumSet<Privilege> privs, byte identity) throws Exception {
        gp.installAndMakeSelectable(gpAID(PKG), gpAID(PKG), gpAID(instance), privs, new byte[]{identity});
    }

    // Install with a second app-specific param byte that drives GlobalPlatformTestApplet.select()
    // to refuse selection.
    private static void installWith(GPSession gp, AID instance, EnumSet<Privilege> privs, byte identity, boolean rejectSelect) throws Exception {
        gp.installAndMakeSelectable(gpAID(PKG), gpAID(PKG), gpAID(instance), privs, new byte[]{identity, (byte) (rejectSelect ? 0x01 : 0x00)});
    }

    // Advance the ISD lifecycle from OP_READY through INITIALIZED to SECURED via SET STATUS
    // on the open ISD session. SCP wraps the APDUs and authenticates the ISD as the caller -
    // the ISD holds AuthorizedManagement by default, which authorizes both transitions.
    private static void advanceToSecured(GPSession gp) throws Exception {
        gp.setCardStatus(ISDLifeCycle.INITIALIZED);
        gp.setCardStatus(ISDLifeCycle.SECURED);
    }

    private static void selectAID(BIBO bibo, AID aid) {
        var r = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AIDUtil.bytes(aid), 256));
        assertEquals(r.getSW(), 0x9000);
    }

    // GPSession only exposes accepted card-LCS transitions, so the rejected ones are hand-built and sent over the authenticated session.
    private static void assertSetStatusRejected(GPSession gp, int newLcs) throws Exception {
        var r = gp.transmit(new CommandAPDU(0x80, INS_SET_STATUS, P1_CARD_LCS, newLcs));
        assertEquals(r.getSW(), 0x6985);
    }

    private static void assertGpSystemReturns(BIBO bibo, byte ins, boolean expected) {
        var r = bibo.transmit(new CommandAPDU(0x00, ins, 0x00, 0x00, 256));
        assertEquals(r.getSW(), 0x9000);
        assertEquals(r.getData().length, 1);
        assertEquals(r.getData()[0], (byte) (expected ? 0x01 : 0x00));
    }
}
