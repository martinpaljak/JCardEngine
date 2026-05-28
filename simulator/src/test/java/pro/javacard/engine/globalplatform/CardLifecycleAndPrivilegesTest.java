// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import org.globalplatform.GPSystem;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.engine.testapplets.GlobalPlatformTestApplet;
import pro.javacard.gp.GPRegistryEntry.ISDLifeCycle;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPSession;

import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
            assertEquals((byte) 0x01, gp.getRegistry().getISD().get().getLifeCycle(),
                    "Fresh card ISD lifecycle must be OP_READY (0x01)");

            // GPC v2.3.1 5.1.1.2: from OP_READY, only INITIALIZED is reachable. Direct skips and self-loop rejected.
            assertSetStatusRejected(gp, 0x0F, "OP_READY -> SECURED skip");
            assertSetStatusRejected(gp, 0x7F, "OP_READY -> CARD_LOCKED skip");
            assertSetStatusRejected(gp, 0x01, "OP_READY -> OP_READY no-op");
            assertEquals((byte) 0x01, gp.getRegistry().getISD().get().getLifeCycle(),
                    "Lifecycle must remain OP_READY after rejected transitions");

            // GPC v2.3.1 Table 11-86: P1 values other than 0x80 (card) and 0x40 (application) are unsupported.
            var p1Bad = gp.transmit(new CommandAPDU(0x80, INS_SET_STATUS, 0x60, 0x07));
            assertEquals(0x6A81, p1Bad.getSW(), "SET STATUS with an unsupported P1 must return 0x6A81");

            // GPC v2.3.1 5.1.1.2: OP_READY -> INITIALIZED.
            gp.setCardStatus(ISDLifeCycle.INITIALIZED);
            assertEquals((byte) 0x07, gp.getRegistry().getISD().get().getLifeCycle());

            // GPC v2.3.1 5.1.1.2: INITIALIZED is irreversible.
            assertSetStatusRejected(gp, 0x01, "INITIALIZED -> OP_READY (irreversible)");

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
            assertSetStatusRejected(gp, 0x0F, "TERMINATED -> SECURED");
            assertSetStatusRejected(gp, 0x07, "TERMINATED -> INITIALIZED");
            assertSetStatusRejected(gp, 0x01, "TERMINATED -> OP_READY");
            assertSetStatusRejected(gp, 0xFF, "TERMINATED -> TERMINATED no-op");
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
            assertGpSystemReturns(bibo, GlobalPlatformTestApplet.INS_LOCK_CARD, false,
                    "lockCard without CardLock");
            assertEquals((byte) 0x0F, openIsd(bibo).getRegistry().getISD().get().getLifeCycle(),
                    "ISD lifecycle must remain SECURED after rejected lockCard");

            selectAID(bibo, B);
            assertGpSystemReturns(bibo, GlobalPlatformTestApplet.INS_LOCK_CARD, true,
                    "lockCard with CardLock from SECURED");
            // GPSystem.getCardState (JC-API view) MUST track the actual ISD lifecycle byte
            // observable via GET STATUS - same source of truth, different surface.
            var rState = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_GET_CARD_STATE, 0x00, 0x00, 256));
            assertEquals(0x9000, rState.getSW());
            assertEquals((byte) 0x7F, rState.getData()[0],
                    "getCardState after lockCard must report CARD_LOCKED (0x7F)");
        }

        // Right privilege, wrong source state: lockCard from OP_READY rejected by GPC v2.3.1 5.1.1.4.
        try (var bibo = freshEngine().connect()) {
            var gp = openIsd(bibo);
            installWith(gp, A, EnumSet.of(Privilege.CardLock));    // no advanceToSecured
            selectAID(bibo, A);
            assertGpSystemReturns(bibo, GlobalPlatformTestApplet.INS_LOCK_CARD, false,
                    "lockCard from OP_READY (state machine rejects)");
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
            assertGpSystemReturns(bibo, GlobalPlatformTestApplet.INS_TERMINATE_CARD, false,
                    "terminateCard without CardTerminate");

            selectAID(bibo, B);
            assertGpSystemReturns(bibo, GlobalPlatformTestApplet.INS_TERMINATE_CARD, true,
                    "terminateCard with CardTerminate");
        }
    }

    // GPC v2.3.1 6.6.2: install with CardReset transfers the privilege from the current holder.
    // After installing A then B both with CardReset, B holds the privilege and auto-selects on
    // reset (its INS_GET_IDENTITY returns ID_B, not ID_A). Deleting B then A returns CardReset
    // to the ISD; the ISD then auto-selects on reset and an unknown INS reaches it (returns
    // SW_SECURITY_STATUS_NOT_SATISFIED rather than 6985 "no applet selected").
    @Test
    public void cardResetTransferAndAutoSelect() throws Exception {
        var sim = freshEngine();
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            installWith(gp, A, EnumSet.of(Privilege.CardReset), ID_A);
            installWith(gp, B, EnumSet.of(Privilege.CardReset), ID_B);
        }
        sim.reset();
        try (var bibo = sim.connect()) {
            var r = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_GET_IDENTITY, 0x00, 0x00, 256));
            assertEquals(0x9000, r.getSW(),
                    "After install B with CardReset, only B (not A) may auto-select on reset");
            assertEquals(1, r.getData().length);
            assertEquals(ID_B, r.getData()[0],
                    "Auto-selected holder identity must be B (0xB2), not A (0xA1)");
        }

        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            gp.deleteAID(gpAID(B), false);
            gp.deleteAID(gpAID(A), false);
        }
        sim.reset();
        try (var bibo = sim.connect()) {
            var r = bibo.transmit(new CommandAPDU(0x00, 0x07, 0x00, 0x00, 256));
            assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, (short) r.getSW(),
                    "After deleting all CardReset holders, ISD must regain CardReset and process APDUs");
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

            var rNull = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_QUERY_SELF, 0x00, 0x00, 256));
            assertEquals(0x9000, rNull.getSW(), "self-query via null");
            assertEquals(GPSystem.APPLICATION_SELECTABLE, rNull.getData()[0]);

            var rSelf = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_QUERY_AID, 0x00, 0x00, AIDUtil.bytes(A), 256));
            assertEquals(0x9000, rSelf.getSW(), "self-query via own AID");
            assertEquals(GPSystem.APPLICATION_SELECTABLE, rSelf.getData()[0]);

            var rCross = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_QUERY_AID, 0x00, 0x00, AIDUtil.bytes(B), 256));
            assertEquals(0x6A82, rCross.getSW(), "Unprivileged cross-applet query must be denied (gate fired)");
        }

        // With GlobalRegistry on A: cross-applet A->B succeeds (returns SELECTABLE for B).
        var sim2 = freshEngine();
        try (var bibo = sim2.connect()) {
            var gp = openIsd(bibo);
            installWith(gp, A, EnumSet.of(Privilege.GlobalRegistry));
            installWith(gp, B, EnumSet.noneOf(Privilege.class));
            selectAID(bibo, A);

            var r = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_QUERY_AID, 0x00, 0x00, AIDUtil.bytes(B), 256));
            assertEquals(0x9000, r.getSW(), "GlobalRegistry-privileged cross-applet query must succeed");
            assertEquals(GPSystem.APPLICATION_SELECTABLE, r.getData()[0]);
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
            assertEquals((byte) 0x01, advance.getData()[0], "advance to 0x0F must be accepted by the OPEN per GPC v2.3.1 5.3.1.5");
            assertEquals((byte) 0x0F, advance.getData()[1], "current state must reflect the accepted transition");

            // Forward again to a higher app-specific state succeeds since the OPEN does not
            // constrain monotonicity of application-specific transitions.
            var advance2 = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS, 0x1F, 0x00, 256));
            assertEquals((byte) 0x01, advance2.getData()[0], "advance to 0x1F must be accepted");
            assertEquals((byte) 0x1F, advance2.getData()[1]);

            // Regression to SELECTABLE (0x07) must be refused since INSTALLED -> SELECTABLE is
            // irreversible per GPC v2.3.1 5.3.1.2 and the resulting state would be lower than
            // the current value, which the canonical setState rules also forbid.
            var regress = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS, 0x07, 0x00, 256));
            assertEquals((byte) 0x00, regress.getData()[0], "regression to SELECTABLE must be refused (GPC v2.3.1 5.3.1.2 irreversibility)");
            assertEquals((byte) 0x1F, regress.getData()[1], "state must remain at 0x1F after refused regression");

            // Regression to INSTALLED (0x03) must be refused for the same reason.
            var toInstalled = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS, 0x03, 0x00, 256));
            assertEquals((byte) 0x00, toInstalled.getData()[0]);
            assertEquals((byte) 0x1F, toInstalled.getData()[1]);

            // Self-LOCK (b8=1, e.g. 0x83) is accepted per GPC v2.3.1 5.3.1.3 which lists "the
            // Application itself" among entities permitted to set LOCKED. Per the API javadoc,
            // b7..b1 of the new state are ignored on lock so the resulting lifecycle is
            // current OR 0x80 = 0x9F rather than the literal 0x83 passed in.
            var selfLock = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS, 0x83, 0x00, 256));
            assertEquals((byte) 0x01, selfLock.getData()[0], "self-LOCK must be accepted per GPC v2.3.1 5.3.1.3 + GP API export file 1.5");
            assertEquals((byte) 0x9F, selfLock.getData()[1], "post-lock state must be (previous OR 0x80) per the API javadoc");

            // After self-lock the applet is no longer in an application-specific state, so any
            // subsequent setCardContentState attempt must fail the API pre-condition (caller
            // must currently be in 0x07..0x7F with low 3 bits set).
            var unlockAttempt = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS, 0x07, 0x00, 256));
            assertEquals((byte) 0x00, unlockAttempt.getData()[0], "self-unlock must be refused since setCardContentState requires caller to be in an application-specific state");
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

            var lock = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS_VIA_REGISTRY, 0x83, 0x00, 256));
            assertEquals((byte) 0x01, lock.getData()[0], "self-LOCK via getRegistryEntry(null).setState must succeed for the same 5.3.1.3 reason");
            assertEquals((byte) 0x87, lock.getData()[1], "post-lock state via setState must be (previous OR 0x80); previous was 0x07 SELECTABLE so result is 0x87");

            var unlock = bibo.transmit(new CommandAPDU(0x00, GlobalPlatformTestApplet.INS_SET_OWN_LCS_VIA_REGISTRY, 0x07, 0x00, 256));
            assertEquals((byte) 0x00, unlock.getData()[0], "self-unlock via setState must be refused since the applet does not hold Global Lock");
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
            assertEquals((byte) 0x07, appLifecycle(gp, A), "newly installed applet must be SELECTABLE");

            // Unknown target AID -> 0x6A88 (referenced data not found).
            var unknown = gp.transmit(new CommandAPDU(0x80, INS_SET_STATUS, 0x40, 0x80, AIDUtil.bytes(B)));
            assertEquals(0x6A88, unknown.getSW(), "SET STATUS P1=0x40 for an unknown AID must return 0x6A88");
        }

        // Lock (P2 b8=1) then unlock (P2 b8=0) the applet via the GPSession helper; the b8 LOCK
        // bit sets/clears the high bit so SELECTABLE 0x07 becomes 0x87 and returns to 0x07.
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            gp.lockUnlockApplet(gpAID(A), true);
            assertEquals((byte) 0x87, appLifecycle(gp, A), "locked applet must be SELECTABLE | 0x80 = 0x87");
        }
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            gp.lockUnlockApplet(gpAID(A), false);
            assertEquals((byte) 0x07, appLifecycle(gp, A), "unlocked applet must return to SELECTABLE 0x07");
        }

        // Illegal transition: SELECTABLE (0x07) -> INSTALLED (0x03) is irreversible (GPC v2.3.1 5.3.1.2) -> 0x6985.
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            var regress = gp.transmit(new CommandAPDU(0x80, INS_SET_STATUS, 0x40, 0x03, AIDUtil.bytes(A)));
            assertEquals(0x6985, regress.getSW(), "SELECTABLE -> INSTALLED must be rejected as an illegal transition");
            assertEquals((byte) 0x07, appLifecycle(gp, A), "lifecycle must remain SELECTABLE after a rejected transition");
        }
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

    // Advance the ISD lifecycle from OP_READY through INITIALIZED to SECURED via SET STATUS
    // on the open ISD session. SCP wraps the APDUs and authenticates the ISD as the caller -
    // the ISD holds AuthorizedManagement by default, which authorizes both transitions.
    private static void advanceToSecured(GPSession gp) throws Exception {
        gp.setCardStatus(ISDLifeCycle.INITIALIZED);
        gp.setCardStatus(ISDLifeCycle.SECURED);
    }

    private static void selectAID(BIBO bibo, AID aid) {
        var r = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AIDUtil.bytes(aid), 256));
        assertEquals(0x9000, r.getSW(), "SELECT " + aid);
    }

    private static void assertSetStatusRejected(GPSession gp, int newLcs, String label) throws Exception {
        var r = gp.transmit(new CommandAPDU(0x80, INS_SET_STATUS, P1_CARD_LCS, newLcs));
        assertEquals(0x6985, r.getSW(), label + " must be rejected");
    }

    private static void assertGpSystemReturns(BIBO bibo, byte ins, boolean expected, String label) {
        var r = bibo.transmit(new CommandAPDU(0x00, ins, 0x00, 0x00, 256));
        assertEquals(0x9000, r.getSW(), label + ": SW");
        assertEquals(1, r.getData().length, label + ": single-byte response");
        assertEquals((byte) (expected ? 0x01 : 0x00), r.getData()[0], label);
    }
}
