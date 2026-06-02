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
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.engine.testapplets.GlobalPlatformTestApplet;
import pro.javacard.gp.GPRegistryEntry.ISDLifeCycle;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPSession;

import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.javacard.engine.globalplatform.GPTestUtils.gpAID;
import static pro.javacard.engine.globalplatform.GPTestUtils.openIsd;

// Card-wide lifecycle (GPC v2.3.1 5.1.1), GPSystem JC-API state surface, CardReset auto-select
// transfer (GPC v2.3.1 6.6.2), and the GlobalRegistry privilege gate (GPC v2.3.1 6.6.1 / 9.6.5).
// Wire-only observability: gp-pro for SCP/registry; raw bibo for the test applet's INS surface
// and the lifecycle SET STATUS reject probes (no GPSession surface for those).
public class CardLifecycleAndPrivilegesTest {

    private static final AID PKG = AIDUtil.create("01020304050607080F");
    private static final AID A = AIDUtil.create("0102030405060708A1");
    private static final AID B = AIDUtil.create("0102030405060708B2");

    private static final byte ID_A = (byte) 0xA1;
    private static final byte ID_B = (byte) 0xB2;

    private static final byte INS_SET_STATUS = (byte) 0xF0;
    private static final byte P1_CARD_LCS = (byte) 0x80;

    // GPC v2.3.1 5.1.1: full ISD lifecycle state machine on one card.
    //   OP_READY (0x01) -> INITIALIZED (0x07) -> SECURED (0x0F) -> CARD_LOCKED (0x7F)
    //                  -> SECURED -> TERMINATED (0xFF)
    // At each source state, every invalid target is rejected with 0x6985 and the lifecycle byte
    // remains unchanged. The ISD performs all transitions using its default privileges
    // (AuthorizedManagement, CardLock, CardTerminate).
    @Test
    public void cardLifecycleStateMachine() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);

            // GPC v2.3.1 5.1.1.1: virgin card boots in OP_READY.
            assertEquals((byte) 0x01, gp.getRegistry().getISD().get().getLifeCycle());

            // GPC v2.3.1 5.1.1.2: from OP_READY, only INITIALIZED is reachable. Direct skips and self-loop rejected.
            assertSetStatusRejected(gp, 0x0F); // OP_READY -> SECURED skip
            assertSetStatusRejected(gp, 0x7F); // OP_READY -> CARD_LOCKED skip
            assertSetStatusRejected(gp, 0x01); // OP_READY -> OP_READY no-op
            // lifecycle unchanged after rejected transitions
            assertEquals((byte) 0x01, gp.getRegistry().getISD().get().getLifeCycle());

            // GPC v2.3.1 Table 11-86: P1 values other than 0x80 (card) and 0x40 (application) are unsupported.
            var p1Bad = gp.transmit(new CommandAPDU(0x80, INS_SET_STATUS, 0x60, 0x07));
            assertEquals(0x6A81, p1Bad.getSW());

            // GPC v2.3.1 5.1.1.2: OP_READY -> INITIALIZED.
            gp.setCardStatus(ISDLifeCycle.INITIALIZED);
            assertEquals((byte) 0x07, gp.getRegistry().getISD().get().getLifeCycle());

            // GPC v2.3.1 5.1.1.2: INITIALIZED is irreversible.
            assertSetStatusRejected(gp, 0x01); // INITIALIZED -> OP_READY (irreversible)

            // GPC v2.3.1 5.1.1.3: INITIALIZED -> SECURED.
            gp.setCardStatus(ISDLifeCycle.SECURED);
            assertEquals((byte) 0x0F, gp.getRegistry().getISD().get().getLifeCycle());

            // GPC v2.3.1 5.1.1.4: post-issuance lock/unlock is reversible (CardLock privilege held by ISD).
            gp.setCardStatus(ISDLifeCycle.CARD_LOCKED);
            assertEquals((byte) 0x7F, gp.getRegistry().getISD().get().getLifeCycle());
            gp.setCardStatus(ISDLifeCycle.SECURED);
            assertEquals((byte) 0x0F, gp.getRegistry().getISD().get().getLifeCycle());

            // GPC v2.3.1 5.1.1.5: TERMINATED is reachable from any non-terminal state (CardTerminate privilege).
            gp.setCardStatus(ISDLifeCycle.TERMINATED);

            // GPC v2.3.1 5.1.1.5: TERMINATED is irreversible - no transition out, including self-loop.
            assertSetStatusRejected(gp, 0x0F); // TERMINATED -> SECURED
            assertSetStatusRejected(gp, 0x07); // TERMINATED -> INITIALIZED
            assertSetStatusRejected(gp, 0x01); // TERMINATED -> OP_READY
            assertSetStatusRejected(gp, 0xFF); // TERMINATED -> TERMINATED no-op
        }
    }

    // GPC v2.3.1 5.1.1.4 / 5.1.1.5: GPSystem.lockCard and GPSystem.terminateCard from inside an
    // applet are gated by privileges (CardLock, CardTerminate) and by source-state preconditions.
    // The applet can't bypass GPC v2.3.1 5.1.1 just by holding a privilege - the JC-API path enforces both.
    @Test
    public void gpSystemCardStateApi() throws Exception {
        // From SECURED: lockCard gated by CardLock; ISD stays SECURED on rejection.
        try (var bibo = freshEngine().connect()) {
            var gp = openIsd(bibo);
            advanceToSecured(gp);
            installWith(gp, A, EnumSet.noneOf(Privilege.class));   // no CardLock
            installWith(gp, B, EnumSet.of(Privilege.CardLock));    // with CardLock

            selectAID(bibo, A);
            // lockCard without CardLock
            assertGpSystemReturns(bibo, GlobalPlatformTestApplet.INS_LOCK_CARD, false);
            // ISD stays SECURED after rejected lockCard
            assertEquals((byte) 0x0F, openIsd(bibo).getRegistry().getISD().get().getLifeCycle());

            selectAID(bibo, B);
            // lockCard with CardLock from SECURED
            assertGpSystemReturns(bibo, GlobalPlatformTestApplet.INS_LOCK_CARD, true);
            // GPSystem.getCardState (JC-API view) MUST track the actual ISD lifecycle byte
            // observable via GET STATUS - same source of truth, different surface.
            var rState = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_GET_CARD_STATE, 0x00, 0x00, 256));
            assertEquals(0x9000, rState.getSW());
            // getCardState reports CARD_LOCKED after lockCard
            assertEquals((byte) 0x7F, rState.getData()[0]);
        }

        // Right privilege, wrong source state: lockCard from OP_READY rejected by GPC v2.3.1 5.1.1.4.
        try (var bibo = freshEngine().connect()) {
            var gp = openIsd(bibo);
            installWith(gp, A, EnumSet.of(Privilege.CardLock));    // no advanceToSecured
            selectAID(bibo, A);
            // lockCard from OP_READY (state machine rejects)
            assertGpSystemReturns(bibo, GlobalPlatformTestApplet.INS_LOCK_CARD, false);
        }

        // terminateCard requires CardTerminate; CardLock alone is insufficient. With the
        // privilege granted, the call succeeds. terminateCard is irreversible, so it must be
        // the last assertion against this card.
        try (var bibo = freshEngine().connect()) {
            var gp = openIsd(bibo);
            advanceToSecured(gp);
            installWith(gp, A, EnumSet.of(Privilege.CardLock));      // not CardTerminate
            installWith(gp, B, EnumSet.of(Privilege.CardTerminate));

            selectAID(bibo, A);
            // terminateCard without CardTerminate
            assertGpSystemReturns(bibo, GlobalPlatformTestApplet.INS_TERMINATE_CARD, false);

            selectAID(bibo, B);
            // terminateCard with CardTerminate
            assertGpSystemReturns(bibo, GlobalPlatformTestApplet.INS_TERMINATE_CARD, true);
        }
    }

    // GPC v2.3.1 6.6.2: install with CardReset transfers the privilege from the current holder.
    // After installing A then B both with CardReset, B holds the privilege and auto-selects on
    // the next power-up (its INS_GET_IDENTITY returns ID_B, not ID_A). Deleting B then A returns CardReset
    // to the ISD; the ISD then auto-selects on power-up and an unknown INS reaches it (returns
    // SW_SECURITY_STATUS_NOT_SATISFIED rather than 6985 "no applet selected"). Finally, a CardReset
    // holder whose select() refuses (JCRE 3.2 4.6.2) leaves nothing selected on power-up, so the
    // following non-SELECT command returns SW_APPLET_SELECT_FAILED 0x6999 (JCRE 3.2 4.8).
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
            // B (last CardReset holder) auto-selects on power-up, not A
            assertEquals(0x9000, r.getSW());
            assertEquals(1, r.getData().length);
            assertEquals(ID_B, r.getData()[0]);
        }

        try (var bibo = sim.connect("*", true)) {
            var gp = openIsd(bibo);
            gp.deleteAID(gpAID(B), false);
            gp.deleteAID(gpAID(A), false);
        }
        try (var bibo = sim.connect()) {
            var r = bibo.transmit(new CommandAPDU(0x00, 0x07, 0x00, 0x00, 256));
            // ISD regains CardReset and processes APDUs once all holders are deleted
            assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, (short) r.getSW());
        }

        // CardReset holder that refuses selection: nothing is selected after power-up.
        var simReject = freshEngine();
        try (var bibo = simReject.connect("*", true)) {
            installWith(openIsd(bibo), A, EnumSet.of(Privilege.CardReset), ID_A, true);
        }
        try (var bibo = simReject.connect()) {
            var r = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_GET_IDENTITY, 0x00, 0x00, 256));
            // JCRE 3.2 4.8: non-SELECT command with no applet selected returns 0x6999
            assertEquals(ISO7816.SW_APPLET_SELECT_FAILED, (short) r.getSW());
        }
    }

    // GP JC API (org.globalplatform): getRegistryEntry on self (null or own AID) must succeed
    // without GlobalRegistry; cross-applet getRegistryEntry requires the GlobalRegistry
    // privilege (GPC v2.3.1 6.6.1 / 9.6.5).
    @Test
    public void globalRegistryGate() throws Exception {
        // Without GlobalRegistry: self-query (both shapes) succeeds; cross-applet denied 6A82.
        var sim1 = freshEngine();
        try (var bibo = sim1.connect()) {
            var gp = openIsd(bibo);
            installWith(gp, A, EnumSet.noneOf(Privilege.class));
            installWith(gp, B, EnumSet.noneOf(Privilege.class));
            selectAID(bibo, A);

            // self-query via null
            var rNull = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_QUERY_SELF, 0x00, 0x00, 256));
            assertEquals(0x9000, rNull.getSW());
            assertEquals(GPSystem.APPLICATION_SELECTABLE, rNull.getData()[0]);

            // self-query via own AID
            var rSelf = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_QUERY_AID, 0x00, 0x00, AIDUtil.bytes(A), 256));
            assertEquals(0x9000, rSelf.getSW());
            assertEquals(GPSystem.APPLICATION_SELECTABLE, rSelf.getData()[0]);

            // unprivileged cross-applet query denied
            var rCross = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_QUERY_AID, 0x00, 0x00, AIDUtil.bytes(B), 256));
            assertEquals(0x6A82, rCross.getSW());
        }

        // With GlobalRegistry on A: cross-applet A->B succeeds (returns SELECTABLE for B).
        var sim2 = freshEngine();
        try (var bibo = sim2.connect()) {
            var gp = openIsd(bibo);
            installWith(gp, A, EnumSet.of(Privilege.GlobalRegistry));
            installWith(gp, B, EnumSet.noneOf(Privilege.class));
            selectAID(bibo, A);

            // GlobalRegistry-privileged cross-applet query succeeds
            var r = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_QUERY_AID, 0x00, 0x00, AIDUtil.bytes(B), 256));
            assertEquals(0x9000, r.getSW());
            assertEquals(GPSystem.APPLICATION_SELECTABLE, r.getData()[0]);

            // getPrivileges returns the 3-byte bitmap; A holds GlobalRegistry, so it is non-zero.
            var privs = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_QUERY_PRIVS, 0x00, 0x00, 256));
            assertEquals(0x9000, privs.getSW());
            assertEquals(3, privs.getData().length);
            assertTrue((privs.getData()[0] | privs.getData()[1] | privs.getData()[2]) != 0);
        }
    }

    // GP API GPSystem.setCardContentState (export file v1.8): an Application updates its own LCS.
    // The OPEN leaves application-specific transitions unconstrained per GPC v2.3.1 5.3.1.5 but
    // enforces irreversibility of the INSTALLED -> SELECTABLE move (5.3.1.2). The 5.3.1.3
    // catalogue of entities allowed to set LOCKED includes "the Application itself", so self-lock
    // is accepted (since GP API export file 1.5) but self-unlock is forbidden by the API contract
    // and only a Global Lock privilege holder can clear the lock via getRegistryEntry().setState().
    // The applet starts at SELECTABLE (0x07).
    @Test
    public void appletSelfLifecycleTransitions() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            installWith(openIsd(bibo), A, EnumSet.noneOf(Privilege.class));
            selectAID(bibo, A);

            // Forward to an app-specific state succeeds and GPSystem.getCardContentState()
            // reflects the new value.
            var advance = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS, 0x0F, 0x00, 256));
            assertEquals(0x9000, advance.getSW());
            // GPC v2.3.1 5.3.1.5: OPEN accepts app-specific forward transition
            assertEquals((byte) 0x01, advance.getData()[0]);
            assertEquals((byte) 0x0F, advance.getData()[1]);

            // Forward again to a higher app-specific state succeeds since the OPEN does not
            // constrain monotonicity of application-specific transitions.
            var advance2 = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS, 0x1F, 0x00, 256));
            assertEquals((byte) 0x01, advance2.getData()[0]);
            assertEquals((byte) 0x1F, advance2.getData()[1]);

            // Regression to SELECTABLE (0x07) must be refused since INSTALLED -> SELECTABLE is
            // irreversible per GPC v2.3.1 5.3.1.2 and the resulting state would be lower than
            // the current value, which the canonical setState rules also forbid.
            var regress = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS, 0x07, 0x00, 256));
            // GPC v2.3.1 5.3.1.2: regression to SELECTABLE refused (irreversibility)
            assertEquals((byte) 0x00, regress.getData()[0]);
            assertEquals((byte) 0x1F, regress.getData()[1]);

            // Regression to INSTALLED (0x03) must be refused for the same reason.
            var toInstalled = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS, 0x03, 0x00, 256));
            assertEquals((byte) 0x00, toInstalled.getData()[0]);
            assertEquals((byte) 0x1F, toInstalled.getData()[1]);

            // Self-LOCK (b8=1, e.g. 0x83) is accepted per GPC v2.3.1 5.3.1.3 which lists "the
            // Application itself" among entities permitted to set LOCKED. Per the API javadoc,
            // b7..b1 of the new state are ignored on lock so the resulting lifecycle is
            // current OR 0x80 = 0x9F rather than the literal 0x83 passed in.
            var selfLock = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS, 0x83, 0x00, 256));
            // GPC v2.3.1 5.3.1.3: self-LOCK accepted; result is previous OR 0x80
            assertEquals((byte) 0x01, selfLock.getData()[0]);
            assertEquals((byte) 0x9F, selfLock.getData()[1]);

            // After self-lock the applet is no longer in an application-specific state, so any
            // subsequent setCardContentState attempt must fail the API pre-condition (caller
            // must currently be in 0x07..0x7F with low 3 bits set).
            var unlockAttempt = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS, 0x07, 0x00, 256));
            // self-unlock refused: caller no longer in an application-specific state
            assertEquals((byte) 0x00, unlockAttempt.getData()[0]);
            assertEquals((byte) 0x9F, unlockAttempt.getData()[1]);
        }
    }

    // The same GP API rules must apply when an applet self-mutates via the alternate path
    // GPSystem.getRegistryEntry(null).setState(...) instead of GPSystem.setCardContentState(...).
    // Both paths converge on the same EngineRegistryEntry.setState() validator, so a self-LOCK
    // succeeds but a self-unlock requires the Global Lock privilege which an ordinary applet
    // does not hold.
    @Test
    public void registryEntrySelfStateMatchesContentStateRules() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            installWith(openIsd(bibo), A, EnumSet.noneOf(Privilege.class));
            selectAID(bibo, A);

            // GPC v2.3.1 5.3.1.3: self-LOCK via setState succeeds; 0x07 OR 0x80 = 0x87
            var lock = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS_VIA_REGISTRY, 0x83, 0x00, 256));
            assertEquals((byte) 0x01, lock.getData()[0]);
            assertEquals((byte) 0x87, lock.getData()[1]);

            // self-unlock via setState refused: applet lacks Global Lock
            var unlock = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS_VIA_REGISTRY, 0x07, 0x00, 256));
            assertEquals((byte) 0x00, unlock.getData()[0]);
            assertEquals((byte) 0x87, unlock.getData()[1]);
        }
    }

    // GPC v2.3.1 11.10 SET STATUS [for application] (P1=0x40): the associated SD (here the ISD,
    // which installed A) locks the applet (P2 b8=1) and unlocks it back. The data field is the
    // target AID, the new state is in P2. GPSession.lockUnlockApplet drives the success path;
    // the reject probes go over the same authenticated session as the card-LCS probes above.
    @Test
    public void applicationSetStatusLockUnlock() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            installWith(gp, A, EnumSet.noneOf(Privilege.class));

            // Freshly made-selectable applet starts at SELECTABLE (0x07).
            assertEquals((byte) 0x07, appLifecycle(gp, A));

            // Unknown target AID -> 0x6A88 (referenced data not found).
            var unknown = gp.transmit(new CommandAPDU(0x80, INS_SET_STATUS, 0x40, 0x80, AIDUtil.bytes(B)));
            assertEquals(0x6A88, unknown.getSW());
        }

        // Lock (P2 b8=1) then unlock (P2 b8=0) the applet via the GPSession helper; the b8 LOCK
        // bit sets/clears the high bit so SELECTABLE 0x07 becomes 0x87 and returns to 0x07.
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            gp.lockUnlockApplet(gpAID(A), true);
            assertEquals((byte) 0x87, appLifecycle(gp, A));
        }
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            gp.lockUnlockApplet(gpAID(A), false);
            assertEquals((byte) 0x07, appLifecycle(gp, A));
        }

        // Illegal transition: SELECTABLE (0x07) -> INSTALLED (0x03) is irreversible (GPC v2.3.1 5.3.1.2) -> 0x6985.
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            var regress = gp.transmit(new CommandAPDU(0x80, INS_SET_STATUS, 0x40, 0x03, AIDUtil.bytes(A)));
            assertEquals(0x6985, regress.getSW());
            assertEquals((byte) 0x07, appLifecycle(gp, A));
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
            assertEquals(0, cvm(bibo, 0x00, 0, null)[0]);
            assertEquals(CVM.CVM_FAILURE, verify(bibo, PIN));
            assertEquals(0, cvm(bibo, 0x05, 0, null)[0]); // resetAndUnblock on INACTIVE
            assertEquals(0, cvm(bibo, 0x04, 0, null)[0]); // block on INACTIVE

            // setTryLimit alone does not activate (no value yet); update installs the value and activates.
            assertEquals(1, cvm(bibo, 0x01, 3, null)[0]);
            assertEquals(0, cvm(bibo, 0x00, 0, null)[0]); // still inactive
            assertEquals(1, cvm(bibo, 0x02, 0, PIN)[0]);   // update, FORMAT_HEX
            byte[] st = cvm(bibo, 0x00, 0, null);
            assertEquals(1, st[0]); // active
            assertEquals(3, st[4]); // tries

            // Non-HEX format is rejected by update.
            assertEquals(0, cvm(bibo, 0x02, FORMAT_ASCII, PIN)[0]);

            // Wrong then right: failure decrements the counter, success validates and restores it.
            assertEquals(CVM.CVM_FAILURE, verify(bibo, WRONG));
            assertEquals(2, cvm(bibo, 0x00, 0, null)[4]);
            assertEquals(CVM.CVM_SUCCESS, verify(bibo, PIN));
            assertEquals(1, cvm(bibo, 0x00, 0, null)[2]); // verified
            assertEquals(3, cvm(bibo, 0x00, 0, null)[4]);

            // resetState drops VALIDATED back to ACTIVE without clearing the value.
            assertEquals(1, cvm(bibo, 0x06, 0, null)[0]);
            assertEquals(0, cvm(bibo, 0x00, 0, null)[2]); // not verified

            // Drive the counter to zero -> BLOCKED; a blocked CVM rejects further verification.
            verify(bibo, WRONG);
            verify(bibo, WRONG);
            verify(bibo, WRONG);
            assertEquals(1, cvm(bibo, 0x00, 0, null)[3]); // blocked
            assertEquals(CVM.CVM_FAILURE, verify(bibo, PIN));

            // setTryLimit(0) is rejected; resetAndUnblock clears BLOCKED and restores the counter.
            assertEquals(0, cvm(bibo, 0x01, 0, null)[0]);
            assertEquals(1, cvm(bibo, 0x05, 0, null)[0]);
            assertEquals(0, cvm(bibo, 0x00, 0, null)[3]); // not blocked
            assertEquals(3, cvm(bibo, 0x00, 0, null)[4]);

            // Explicit block then unblock, then validate to set up the power-up reset probe below.
            assertEquals(1, cvm(bibo, 0x04, 0, null)[0]);
            assertEquals(1, cvm(bibo, 0x05, 0, null)[0]);
            assertEquals(CVM.CVM_SUCCESS, verify(bibo, PIN));

            // B lacks CVM Management: every management op fails, regardless of CVM state.
            selectAID(bibo, B);
            assertEquals(0, cvm(bibo, 0x01, 5, null)[0]); // setTryLimit
            assertEquals(0, cvm(bibo, 0x02, 0, PIN)[0]);  // update
            assertEquals(0, cvm(bibo, 0x04, 0, null)[0]); // block
            assertEquals(0, cvm(bibo, 0x05, 0, null)[0]); // resetAndUnblock
        }

        // Power-up returns the VALIDATED PIN to ACTIVE.
        try (var bibo = sim.connect("*", true)) { // reset on close so the block below survives into the next phase
            selectAID(bibo, A);
            assertEquals(0, cvm(bibo, 0x00, 0, null)[2]); // no longer verified
            assertEquals(1, cvm(bibo, 0x00, 0, null)[0]); // still active
            assertEquals(1, cvm(bibo, 0x04, 0, null)[0]); // block it
        }
        // BLOCKED survives a power-up.
        try (var bibo = sim.connect()) {
            selectAID(bibo, A);
            assertEquals(1, cvm(bibo, 0x00, 0, null)[3]); // still blocked
        }
    }

    // Drive the test applet's CVM sub-op (INS_CVM). data == null for the no-argument ops.
    private static byte[] cvm(BIBO bibo, int p1, int p2, byte[] data) {
        var c = data == null
                ? new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_CVM, p1, p2, 256)
                : new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_CVM, p1, p2, data, 256);
        var r = bibo.transmit(c);
        assertEquals(0x9000, r.getSW());
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

    // GPC v2.3.1 Table 11-43: the Card Reset privilege cannot be set on an INSTALL [for install]
    // that does not also make the Application selectable in the same command. The engine must
    // reject this with 0x6A80 before any registry mutation. GPSession models only the combined
    // install-and-make-selectable (P1=0x0C); the install-only P1=0x04 case is driven over the
    // authenticated session the same way the SET STATUS reject probes above are.
    @Test
    public void cardResetRequiresMakeSelectable() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            // INSTALL [for install] only (P1=0x04, no make-selectable) carrying Card Reset is rejected.
            var r = gp.transmit(installOnlyCommand(A, EnumSet.of(Privilege.CardReset)));
            assertEquals(0x6A80, r.getSW());

            // Same install-only command without Card Reset is accepted, proving 0x04 itself works.
            var ok = gp.transmit(installOnlyCommand(B, EnumSet.noneOf(Privilege.class)));
            assertEquals(0x9000, ok.getSW());
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
        assertEquals(0x9000, r.getSW());
    }

    private static void assertSetStatusRejected(GPSession gp, int newLcs) throws Exception {
        var r = gp.transmit(new CommandAPDU(0x80, INS_SET_STATUS, P1_CARD_LCS, newLcs));
        assertEquals(0x6985, r.getSW());
    }

    private static void assertGpSystemReturns(BIBO bibo, byte ins, boolean expected) {
        var r = bibo.transmit(new CommandAPDU(0x00, ins, 0x00, 0x00, 256));
        assertEquals(0x9000, r.getSW());
        assertEquals(1, r.getData().length);
        assertEquals((byte) (expected ? 0x01 : 0x00), r.getData()[0]);
    }
}
