// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.engine.testapplets.CRELTestApplet;
import pro.javacard.engine.testapplets.CRSTestApplet;
import pro.javacard.engine.testapplets.GlobalPlatformTestApplet;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPSession;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.Tag;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.javacard.engine.globalplatform.GPTestUtils.gpAID;
import static pro.javacard.engine.globalplatform.GPTestUtils.openIsd;

// CRS surface + CREL notification pipeline (GPC v2.3.1 Amd C 3.8, 3.10, 3.11, 7.x, 8.x). CRS driven
// over raw CommandAPDUs (v1 has no SCP wrap); ISD lifecycle goes through GPSession.
public class ContactlessRegistryTest {

    // GPC v2.3.1 Amd C 3.11.1: well-known CRS AID.
    private static final AID CRS_AID = AIDUtil.create("A00000015143525300");

    // Host (X) and CREL target (T) AIDs used across scenarios.
    private static final AID PKG = AIDUtil.create("01020304050607080F");
    private static final AID X = AIDUtil.create("D2450000007702BBBB");
    private static final AID X2 = AIDUtil.create("D2450000007702CCCC");
    private static final AID T = AIDUtil.create("D24500000077010101");

    // CRS APDU surface (engine-side mirror of EngineCRSApplet's private constants).
    private static final byte CRS_CLA = (byte) 0x80;
    private static final byte INS_GET_STATUS = (byte) 0xF2;
    private static final byte INS_SET_STATUS = (byte) 0xF0;
    private static final byte INS_GET_DATA = (byte) 0xCA;
    private static final byte P1_SET_AVAILABILITY = (byte) 0x01;
    private static final byte P1_GET_APPLICATIONS = (byte) 0x40;
    private static final byte P1_GET_DATA = (byte) 0x00;
    private static final byte P2_GET_DATA = (byte) 0xA5;

    // CL event constants (CLAppletEvent).
    private static final short EVENT_ACTIVATED = 0x0002;
    private static final short EVENT_DEACTIVATED = (short) 0x0082;
    private static final short EVENT_SELECTABLE = 0x0012;
    private static final short EVENT_DELETED = 0x0014;
    private static final short EVENT_CREL_ADDED = 0x000E;

    // CL state byte values (GPCLRegistryEntry).
    private static final byte STATE_CL_DEACTIVATED = 0x00;
    private static final byte STATE_CL_ACTIVATED = 0x01;
    private static final byte STATE_CL_NON_ACTIVATABLE = (byte) 0x80;

    // CRELTestApplet APDU surface.
    private static final byte CREL_CLA = (byte) 0x80;
    private static final byte CREL_INS_DUMP = (byte) 0xEE;
    private static final byte CREL_P1_READ = (byte) 0x00;
    private static final byte CREL_P1_SELF_SETCLSTATE = (byte) 0x03;
    private static final byte CREL_P1_CROSS_SETCLSTATE = (byte) 0x04;
    private static final byte CREL_P1_READ_SELF = (byte) 0x05;

    // CRS happy path: SELECT, GET DATA, INSTALL fan-out, GET STATUS, SET STATUS, DELETE
    // (with GPC v2.3.1 Amd C 3.10.4 self-dispatch suppression), reinstall.
    @Test
    public void crsLifecycleAndEvents() throws Exception {
        var sim = freshEngine();

        // 1. Fresh CRS at well-known AID. FCI Table 3-30: 6F { 84 <AID>, A5 { 9F08 0100, 80 <ctr> } }, ctr=0.
        byte[] initialCounter;
        try (var bibo = sim.connect()) {
            initialCounter = parseUpdateCounter(selectAID(bibo, CRS_AID));
            assertArrayEquals(new byte[]{0x00, 0x00}, initialCounter);
        }

        // 2. GET DATA P1=00 P2=A5 returns the A5 template byte-identical to the SELECT FCI;
        // repeated SELECTs do not advance the counter (GPC v2.3.1 Amd C 3.11.6).
        try (var bibo = sim.connect()) {
            byte[] fci = selectAID(bibo, CRS_AID);
            byte[] fromSelect = innerProprietaryBytes(fci);
            var resp = bibo.transmit(new CommandAPDU(CRS_CLA, INS_GET_DATA, P1_GET_DATA, P2_GET_DATA, 256));
            assertEquals(0x9000, resp.getSW());
            assertArrayEquals(fromSelect, resp.getData());
        }
        try (var bibo = sim.connect()) {
            byte[] second = parseUpdateCounter(selectAID(bibo, CRS_AID));
            assertArrayEquals(initialCounter, second);
        }

        // 3. INSTALL X with CREL add-list at T and initial activation 0x01. CREL observes
        // EVENT_CREL_ADDED, EVENT_SELECTABLE, EVENT_ACTIVATED (GPC v2.3.1 Amd C 3.8.3 + 3.10.2).
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            installCRELTestApplet(gp);
            installXWithParams(gp, buildEf(true, T));
        }
        try (var bibo = sim.connect()) {
            var events = dumpCrelEvents(bibo);
            assertEquals(3, events.size());
            assertEvent(events.get(0), EVENT_CREL_ADDED, X);
            assertEvent(events.get(1), EVENT_SELECTABLE, X);
            assertEvent(events.get(2), EVENT_ACTIVATED, X);
        }

        // 4. X is ACTIVATED; update counter advanced by 3 - per-mutation bumps: INSTALL T, INSTALL X,
        // and X's initial CL activation (GPC v2.3.1 Amd C 3.11.2.3, each install/delete/counter event counts).
        try (var bibo = sim.connect()) {
            assertEquals(STATE_CL_ACTIVATED, findClStateInGetStatus(bibo, X));
        }
        try (var bibo = sim.connect()) {
            selectAID(bibo, CRS_AID);
            int viaGetData = readGetDataCounter(bibo);
            assertEquals(3, viaGetData);
        }

        // 5. SET STATUS P1=01 P2=00 flips X to DEACTIVATED; CREL observes EVENT_DEACTIVATED,
        // state persists (GPC v2.3.1 Amd C 3.11.4.2.1 + 3.10.2).
        try (var bibo = sim.connect()) {
            selectAID(bibo, CRS_AID);
            byte[] data = TLV.of(Tag.ber(0x4F), AIDUtil.bytes(X)).encode();
            var resp = bibo.transmit(new CommandAPDU(CRS_CLA, INS_SET_STATUS, P1_SET_AVAILABILITY, STATE_CL_DEACTIVATED, data));
            assertEquals(0x9000, resp.getSW());
        }
        try (var bibo = sim.connect()) {
            var events = dumpCrelEvents(bibo);
            assertEquals(4, events.size());
            assertEvent(events.get(3), EVENT_DEACTIVATED, X);
        }
        try (var bibo = sim.connect()) {
            assertEquals(STATE_CL_DEACTIVATED, findClStateInGetStatus(bibo, X));
        }

        // 6. DELETE fires EVENT_DELETED to the host's CREL list but NOT to the host itself
        // (GPC v2.3.1 Amd C 3.10.2 + 3.10.4 self-dispatch suppression). Snapshot X's self log first.
        try (var bibo = sim.connect()) {
            selectAID(bibo, X);
            var dump = bibo.transmit(new CommandAPDU(CREL_CLA, CREL_INS_DUMP, CREL_P1_READ_SELF, 0x00, 256));
            assertEquals(0x9000, dump.getSW());
            // Self log records: event(2) | prev-null(1); prev-null must be 0x01 for every record.
            byte[] data = dump.getData();
            for (int i = 0; i < data.length; i += 3) {
                short ev = (short) (((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF));
                assertFalse(ev == EVENT_DELETED);
                assertEquals((byte) 0x01, data[i + 2]);
            }
        }
        try (var bibo = sim.connect()) {
            openIsd(bibo).deleteAID(gpAID(X), false);
        }
        try (var bibo = sim.connect()) {
            var events = dumpCrelEvents(bibo);
            assertEvent(events.get(events.size() - 1), EVENT_DELETED, X);
        }

        // 7. Re-install X (T re-listed) and confirm T resumes receiving events (GPC v2.3.1 Amd C 3.8.2).
        try (var bibo = sim.connect()) {
            installXWithParams(openIsd(bibo), buildEf(false, T));
        }
        int eventsBeforeActivate;
        try (var bibo = sim.connect()) {
            eventsBeforeActivate = dumpCrelEvents(bibo).size();
        }
        try (var bibo = sim.connect()) {
            selectAID(bibo, CRS_AID);
            byte[] data = TLV.of(Tag.ber(0x4F), AIDUtil.bytes(X)).encode();
            var resp = bibo.transmit(new CommandAPDU(CRS_CLA, INS_SET_STATUS, P1_SET_AVAILABILITY, STATE_CL_ACTIVATED, data));
            assertEquals(0x9000, resp.getSW());
        }
        try (var bibo = sim.connect()) {
            var events = dumpCrelEvents(bibo);
            assertEquals(eventsBeforeActivate + 1, events.size());
            assertEvent(events.get(events.size() - 1), EVENT_ACTIVATED, X);
        }
    }

    // CRS APDU contract: well-formed paths (paging, match-all, multi-AID, mixed warning) and
    // malformed/parameter-bound rejections (GPC v2.3.1 Amd C 3.11).
    @Test
    public void crsApduContract() throws Exception {
        // 1. Paging: 20 CL applets push GET STATUS past 256 bytes. First chunk 6310, P2 bit 0=1
        // continuations, 9000 terminates; stale continuation after 9000 -> 6985 (Table 3-16).
        var sim = new JavaCardEngine.Builder().build();
        int n = 20;
        var aids = new ArrayList<AID>();
        for (int i = 0; i < n; i++) {
            byte[] raw = new byte[]{(byte) 0xD2, 0x45, 0x00, 0x00, 0x00, 0x77, 0x10, 0x00, (byte) i};
            var aid = AIDUtil.create(raw);
            aids.add(aid);
            sim.loadApplet(PKG, aid, GlobalPlatformTestApplet.class);
        }
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            for (var aid : aids) {
                gp.installAndMakeSelectable(gpAID(PKG), gpAID(aid), gpAID(aid),
                        EnumSet.noneOf(Privilege.class), new byte[0]);
            }
        }
        try (var bibo = sim.connect()) {
            selectAID(bibo, CRS_AID);
            byte[] filter = TLV.of(Tag.ber(0x4F), new byte[0]).encode();
            var first = bibo.transmit(new CommandAPDU(CRS_CLA, INS_GET_STATUS, P1_GET_APPLICATIONS, 0x00, filter, 256));
            assertEquals(0x6310, first.getSW());
            assertTrue(first.getData().length > 0);

            // Restart mid-paging: a fresh initial call (P2 bit 0 = 0) must succeed.
            var restart = bibo.transmit(new CommandAPDU(CRS_CLA, INS_GET_STATUS, P1_GET_APPLICATIONS, 0x00, filter, 256));
            assertTrue(restart.getSW() == 0x6310 || restart.getSW() == 0x9000);

            // Drain the restarted sequence; every installed AID present in the reassembled body.
            var assembled = new ByteArrayOutputStream();
            assembled.writeBytes(restart.getData());
            var resp = restart;
            int chunks = 1;
            while (resp.getSW() == 0x6310) {
                resp = bibo.transmit(new CommandAPDU(CRS_CLA, INS_GET_STATUS, P1_GET_APPLICATIONS, 0x01, filter, 256));
                assembled.writeBytes(resp.getData());
                chunks++;
            }
            assertEquals(0x9000, resp.getSW());
            assertTrue(chunks >= 2);
            var entries = TLV.parse(assembled.toByteArray());
            var seen = new ArrayList<AID>();
            for (var entry : entries) {
                assertEquals(Tag.ber(0x61), entry.tag());
                var aidTlv = TLV.find(TLV.parse(entry.value()), Tag.ber(0x4F)).orElse(null);
                if (aidTlv != null) {
                    seen.add(AIDUtil.create(aidTlv.value()));
                }
            }
            for (var aid : aids) {
                assertTrue(seen.contains(aid));
            }

            // Stale continuation after 9000 -> 6985 (GPC v2.3.1 Amd C 3.11.3.2.2).
            var stale = bibo.transmit(new CommandAPDU(CRS_CLA, INS_GET_STATUS, P1_GET_APPLICATIONS, 0x01, filter, 256));
            assertEquals(0x6985, stale.getSW());
        }

        // 2. Multi-AID SET STATUS processes each 4F in command order (GPC v2.3.1 Amd C Table 3-23).
        // X and X2 (sharing CREL T) flipped ACTIVATED in one shot; both EVENT_ACTIVATED in order.
        var simMulti = freshEngine();
        simMulti.loadApplet(PKG, X2, GlobalPlatformTestApplet.class);
        try (var bibo = simMulti.connect()) {
            var gp = openIsd(bibo);
            installCRELTestApplet(gp);
            installXWithParams(gp, buildEf(false, T));
            installAtAidWithParams(gp, X2, buildEf(false, T));
        }
        try (var bibo = simMulti.connect()) {
            selectAID(bibo, CRS_AID);
            byte[] data = TLV.encode(
                    TLV.of(Tag.ber(0x4F), AIDUtil.bytes(X)),
                    TLV.of(Tag.ber(0x4F), AIDUtil.bytes(X2)));
            var resp = bibo.transmit(new CommandAPDU(CRS_CLA, INS_SET_STATUS, P1_SET_AVAILABILITY, STATE_CL_ACTIVATED, data));
            assertEquals(0x9000, resp.getSW());
        }
        try (var bibo = simMulti.connect()) {
            assertEquals(STATE_CL_ACTIVATED, findClStateInGetStatus(bibo, X));
            assertEquals(STATE_CL_ACTIVATED, findClStateInGetStatus(bibo, X2));
        }
        try (var bibo = simMulti.connect()) {
            var events = dumpCrelEvents(bibo);
            assertEquals(6, events.size());
            var tail = events.subList(events.size() - 2, events.size());
            assertEvent(tail.get(0), EVENT_ACTIVATED, X);
            assertEvent(tail.get(1), EVENT_ACTIVATED, X2);
        }

        // 3. Mixed SET STATUS: valid X + unknown AID -> X transitions, unknown lands in A1
        // failed list, SW=6320 (GPC v2.3.1 Amd C 3.11.4.3.1).
        var simMixed = freshEngine();
        try (var bibo = simMixed.connect()) {
            var gp = openIsd(bibo);
            installCRELTestApplet(gp);
            installXWithParams(gp, buildEf(false, T));
        }
        byte[] unknown = Hex.decode("DEADBEEF00");
        try (var bibo = simMixed.connect()) {
            selectAID(bibo, CRS_AID);
            byte[] data = TLV.encode(
                    TLV.of(Tag.ber(0x4F), AIDUtil.bytes(X)),
                    TLV.of(Tag.ber(0x4F), unknown));
            var resp = bibo.transmit(new CommandAPDU(CRS_CLA, INS_SET_STATUS, P1_SET_AVAILABILITY, STATE_CL_ACTIVATED, data));
            assertEquals(0x6320, resp.getSW());
            var parsed = TLV.parse(resp.getData());
            assertEquals(1, parsed.size());
            var a1 = parsed.get(0);
            assertEquals(Tag.ber(0xA1), a1.tag());
            var failed = TLV.parse(a1.value());
            assertEquals(1, failed.size());
            assertEquals(Tag.ber(0x4F), failed.get(0).tag());
            assertArrayEquals(unknown, failed.get(0).value());
        }
        try (var bibo = simMixed.connect()) {
            assertEquals(STATE_CL_ACTIVATED, findClStateInGetStatus(bibo, X));
        }

        // 4. Malformed / parameter-bound rejections.
        var simNeg = new JavaCardEngine.Builder().build();
        try (var bibo = simNeg.connect()) {
            selectAID(bibo, CRS_AID);

            // GET STATUS absent data field -> 6A80 (GPC v2.3.1 Amd C 3.11.3.2.3).
            var absent = bibo.transmit(new CommandAPDU(CRS_CLA, INS_GET_STATUS, P1_GET_APPLICATIONS, 0x00, 256));
            assertEquals(0x6A80, absent.getSW());

            // GET STATUS without any 4F tag in the data field -> 6A80.
            byte[] no4f = TLV.of(Tag.ber(0x5C), new byte[]{0x4F}).encode();
            var missing = bibo.transmit(new CommandAPDU(CRS_CLA, INS_GET_STATUS, P1_GET_APPLICATIONS, 0x00, no4f, 256));
            assertEquals(0x6A80, missing.getSW());

            // Empty 4F is the "match all" sentinel; returns CL entries, each in a 61 template.
            byte[] match = TLV.of(Tag.ber(0x4F), new byte[0]).encode();
            byte[] body = getStatusAll(bibo);
            assertTrue(body.length > 0);
            for (var e : TLV.parse(body)) {
                assertEquals(Tag.ber(0x61), e.tag());
            }

            // RFU bit in P2 (only bit 0 defined, Table 3-13) -> 6A86.
            var rfu = bibo.transmit(new CommandAPDU(CRS_CLA, INS_GET_STATUS, P1_GET_APPLICATIONS, 0x02, match, 256));
            assertEquals(0x6A86, rfu.getSW());

            // Continuation with no prior 6310 -> 6985 (GPC v2.3.1 Amd C 3.11.3.2.2).
            var cont = bibo.transmit(new CommandAPDU(CRS_CLA, INS_GET_STATUS, P1_GET_APPLICATIONS, 0x01, match, 256));
            assertEquals(0x6985, cont.getSW());

            // GET DATA wrong P1/P2 -> 6A86 (only P1=00 P2=A5 defined, GPC v2.3.1 Amd C Table 3-31).
            var badP1 = bibo.transmit(new CommandAPDU(CRS_CLA, INS_GET_DATA, 0x01, P2_GET_DATA, 256));
            assertEquals(0x6A86, badP1.getSW());
            var badP2 = bibo.transmit(new CommandAPDU(CRS_CLA, INS_GET_DATA, P1_GET_DATA, 0x00, 256));
            assertEquals(0x6A86, badP2.getSW());
            var badBoth = bibo.transmit(new CommandAPDU(CRS_CLA, INS_GET_DATA, 0x02, 0xC0, 256));
            assertEquals(0x6A86, badBoth.getSW());

            // SET STATUS unknown AID -> 6320 + A1 list with the failed AID (GPC v2.3.1 Amd C 3.11.4.3.1).
            byte[] unkAid = Hex.decode("A1A2A3A4A5");
            byte[] unkData = TLV.of(Tag.ber(0x4F), unkAid).encode();
            var unk = bibo.transmit(new CommandAPDU(CRS_CLA, INS_SET_STATUS, P1_SET_AVAILABILITY, STATE_CL_ACTIVATED, unkData));
            assertEquals(0x6320, unk.getSW());
            var unkParsed = TLV.parse(unk.getData());
            assertEquals(1, unkParsed.size());
            assertEquals(Tag.ber(0xA1), unkParsed.get(0).tag());
            var unkInner = TLV.parse(unkParsed.get(0).value());
            assertEquals(1, unkInner.size());
            assertEquals(Tag.ber(0x4F), unkInner.get(0).tag());
            assertArrayEquals(unkAid, unkInner.get(0).value());

            // Malformed TLV: "4F 05 A1" declares 5 bytes but supplies 1 -> 6A80.
            var malformed = bibo.transmit(new CommandAPDU(CRS_CLA, INS_SET_STATUS, P1_SET_AVAILABILITY, STATE_CL_ACTIVATED, Hex.decode("4F05A1")));
            assertEquals(0x6A80, malformed.getSW());

            // CRS data field is a sequence of top-level 4F primitives; a 61-wrapped 4F must NOT
            // be accepted as top-level (GPC v2.3.1 Amd C Tables 3-14 / 3-23) -> both 6A80.
            byte[] wrappedAid = TLV.build(Tag.ber(0x61)).add(Tag.ber(0x4F), AIDUtil.bytes(X)).encode();
            var wrappedSet = bibo.transmit(new CommandAPDU(CRS_CLA, INS_SET_STATUS, P1_SET_AVAILABILITY, STATE_CL_ACTIVATED, wrappedAid));
            assertEquals(0x6A80, wrappedSet.getSW());
            byte[] wrappedFilter = TLV.build(Tag.ber(0x61)).add(Tag.ber(0x4F), new byte[0]).encode();
            var wrappedGet = bibo.transmit(new CommandAPDU(CRS_CLA, INS_GET_STATUS, P1_GET_APPLICATIONS, 0x00, wrappedFilter, 256));
            assertEquals(0x6A80, wrappedGet.getSW());

            // SET STATUS P2=NON_ACTIVATABLE rejected: only the applet itself may enter it
            // (GPC v2.3.1 Amd C 3.11.4.2.2) -> 6A86.
            byte[] xData = TLV.of(Tag.ber(0x4F), AIDUtil.bytes(X)).encode();
            var na = bibo.transmit(new CommandAPDU(CRS_CLA, INS_SET_STATUS, P1_SET_AVAILABILITY, STATE_CL_NON_ACTIVATABLE, xData));
            assertEquals(0x6A86, na.getSW());

            // Wrong CLA (anything outside {0x80, 0x84}) -> 6E00.
            var wrongCla = bibo.transmit(new CommandAPDU(0x00, INS_GET_STATUS, P1_GET_APPLICATIONS, 0x00));
            assertEquals(0x6E00, wrongCla.getSW());
        }
    }

    // Privilege gates for setCLState and the install-time ContactlessActivation single-holder
    // rule (GPC v2.3.1 Amd C 7.1 + 7.2 + 8.1). Drives self (P1=03) and cross (P1=04) transitions.
    @Test
    public void privilegeGates() throws Exception {
        // 1. CRELTestApplet at T, no privileges:
        //   - self-ACTIVATE routes to CRS.processCLRequest (default allow) -> 9000 + EVENT_ACTIVATED.
        //   - self-DEACTIVATE needs no privilege (GPC v2.3.1 Amd C 7.2).
        //   - unknown state bytes -> 6982 (CRS only adjudicates EVENT_ACTIVATED).
        var simSelf = freshEngine();
        try (var bibo = simSelf.connect()) {
            installCRELTestApplet(openIsd(bibo));
        }
        try (var bibo = simSelf.connect()) {
            selectAID(bibo, T);
            var crsAllowed = bibo.transmit(new CommandAPDU(CREL_CLA, CREL_INS_DUMP, CREL_P1_SELF_SETCLSTATE, STATE_CL_ACTIVATED));
            assertEquals(0x9000, crsAllowed.getSW());
            assertEquals(STATE_CL_ACTIVATED, crsAllowed.getData()[0]);

            // CRS-routed activation fires EVENT_ACTIVATED; T sees it on its own CLApplet selfLog.
            var selfDump = bibo.transmit(new CommandAPDU(CREL_CLA, CREL_INS_DUMP, (byte) 0x05, 0x00, 256));
            assertEquals(0x9000, selfDump.getSW());
            byte[] selfData = selfDump.getData();
            assertTrue(selfData.length >= 3);
            short lastSelfEvent = (short) (((selfData[selfData.length - 3] & 0xFF) << 8) | (selfData[selfData.length - 2] & 0xFF));
            assertEquals(EVENT_ACTIVATED, lastSelfEvent);

            var allow = bibo.transmit(new CommandAPDU(CREL_CLA, CREL_INS_DUMP, CREL_P1_SELF_SETCLSTATE, STATE_CL_DEACTIVATED));
            assertEquals(0x9000, allow.getSW());
            assertEquals(STATE_CL_DEACTIVATED, allow.getData()[0]);

            // Only ACTIVATED is CRS-mediated; unknown state bytes -> 6982 before the CRS hook.
            var probeBad = bibo.transmit(new CommandAPDU(CREL_CLA, CREL_INS_DUMP, CREL_P1_SELF_SETCLSTATE, 0x02));
            assertEquals(0x6982, probeBad.getSW());
            var probeNa = bibo.transmit(new CommandAPDU(CREL_CLA, CREL_INS_DUMP, CREL_P1_SELF_SETCLSTATE, 0xFF));
            assertEquals(0x6982, probeNa.getSW());
        }

        // 2. Self-ACTIVATE with ContactlessSelfActivation succeeds; EVENT_ACTIVATED fans out to
        // the host's CRELs. Observer t2 listens (originator-aware fan-out skips the host).
        var simSelfOK = new JavaCardEngine.Builder().build();
        simSelfOK.loadApplet(PKG, T, CRELTestApplet.class);
        var t2 = AIDUtil.create("D2450000007701020D");
        simSelfOK.loadApplet(PKG, t2, CRELTestApplet.class);
        try (var bibo = simSelfOK.connect()) {
            var gp = openIsd(bibo);
            gp.installAndMakeSelectable(gpAID(PKG), gpAID(t2), gpAID(t2), EnumSet.noneOf(Privilege.class), new byte[0]);
            byte[] combined = TLV.encode(TLV.of(Tag.ber(0xC9), new byte[]{0x00}), buildEf(false, t2));
            gp.installAndMakeSelectable(gpAID(PKG), gpAID(T), gpAID(T), EnumSet.of(Privilege.ContactlessSelfActivation), combined);
        }
        try (var bibo = simSelfOK.connect()) {
            selectAID(bibo, T);
            var resp = bibo.transmit(new CommandAPDU(CREL_CLA, CREL_INS_DUMP, CREL_P1_SELF_SETCLSTATE, STATE_CL_ACTIVATED));
            assertEquals(0x9000, resp.getSW());
            assertEquals(STATE_CL_ACTIVATED, resp.getData()[0]);
        }
        try (var bibo = simSelfOK.connect()) {
            selectAID(bibo, t2);
            var dump = bibo.transmit(new CommandAPDU(CREL_CLA, CREL_INS_DUMP, CREL_P1_READ, 0x00, 256));
            assertEquals(0x9000, dump.getSW());
            byte[] data = dump.getData();
            // Record layout: event(2) | aid-len(1) | aid bytes | prev-null(1).
            int last = -1;
            int i = 0;
            while (i < data.length) {
                last = i;
                int aidLen = data[i + 2] & 0xFF;
                i += 3 + aidLen + 1;
            }
            assertTrue(last >= 0);
            short event = (short) (((data[last] & 0xFF) << 8) | (data[last + 1] & 0xFF));
            assertEquals(EVENT_ACTIVATED, event);
            int aidLen = data[last + 2] & 0xFF;
            byte[] aid = Arrays.copyOfRange(data, last + 3, last + 3 + aidLen);
            assertArrayEquals(AIDUtil.bytes(T), aid);
            assertEquals((byte) 0x01, data[last + 3 + aidLen]); // prev-null flag
        }

        // 3. Cross-applet ACTIVATE needs ContactlessActivation (GPC v2.3.1 Amd C 7.1). Caller T has
        // GlobalRegistry but not ContactlessActivation -> 6982, X stays DEACTIVATED.
        var simCross = new JavaCardEngine.Builder().build();
        simCross.loadApplet(PKG, T, CRELTestApplet.class);
        simCross.loadApplet(PKG, X, GlobalPlatformTestApplet.class);
        try (var bibo = simCross.connect()) {
            var gp = openIsd(bibo);
            gp.installAndMakeSelectable(gpAID(PKG), gpAID(T), gpAID(T), EnumSet.of(Privilege.GlobalRegistry), new byte[0]);
            gp.installAndMakeSelectable(gpAID(PKG), gpAID(X), gpAID(X), EnumSet.noneOf(Privilege.class), new byte[0]);
        }
        try (var bibo = simCross.connect()) {
            selectAID(bibo, T);
            var resp = bibo.transmit(new CommandAPDU(CREL_CLA, CREL_INS_DUMP, CREL_P1_CROSS_SETCLSTATE, STATE_CL_ACTIVATED, AIDUtil.bytes(X)));
            assertEquals(0x6982, resp.getSW());
        }
        try (var bibo = simCross.connect()) {
            assertEquals(STATE_CL_DEACTIVATED, findClStateInGetStatus(bibo, X));
        }

        // 4. Cross-applet ACTIVATE with the privilege succeeds; EVENT_ACTIVATED on the target's
        // CREL fan-out. Caller picks up ContactlessActivation via install-time TRANSFER (7.1).
        var simCrossOK = new JavaCardEngine.Builder().build();
        simCrossOK.loadApplet(PKG, T, CRELTestApplet.class);
        simCrossOK.loadApplet(PKG, X, GlobalPlatformTestApplet.class);
        var caller = AIDUtil.create("D24500000077029999");
        simCrossOK.loadApplet(PKG, caller, CRELTestApplet.class);
        try (var bibo = simCrossOK.connect()) {
            var gp = openIsd(bibo);
            installCRELTestApplet(gp);
            installXWithParams(gp, buildEf(false, T));
            gp.installAndMakeSelectable(gpAID(PKG), gpAID(caller), gpAID(caller),
                    EnumSet.of(Privilege.GlobalRegistry, Privilege.ContactlessActivation), new byte[0]);
        }
        try (var bibo = simCrossOK.connect()) {
            selectAID(bibo, caller);
            var resp = bibo.transmit(new CommandAPDU(CREL_CLA, CREL_INS_DUMP, CREL_P1_CROSS_SETCLSTATE, STATE_CL_ACTIVATED, AIDUtil.bytes(X)));
            assertEquals(0x9000, resp.getSW());
            assertEquals(STATE_CL_ACTIVATED, resp.getData()[0]);
        }
        try (var bibo = simCrossOK.connect()) {
            var events = dumpCrelEvents(bibo);
            var last = events.get(events.size() - 1);
            assertEquals(EVENT_ACTIVATED, eventOf(last));
            assertEquals(X, targetOf(last));
        }

        // 5. Install-time semantics. ContactlessActivation is single-holder (GPC v2.3.1 Amd C 7.1):
        // INSTALL asking for it TRANSFERs from the planted CRS atomically. ContactlessSelfActivation
        // has no count limit (7.2). INSTALL with initial-activation 0x01 on an unprivileged applet
        // succeeds: install-time setCLState runs in SD context (8.3), bypassing both gates.
        var simInstall = new JavaCardEngine.Builder().build();
        simInstall.loadApplet(PKG, X, GlobalPlatformTestApplet.class);
        simInstall.loadApplet(PKG, X2, GlobalPlatformTestApplet.class);
        try (var bibo = simInstall.connect()) {
            var gp = openIsd(bibo);
            gp.installAndMakeSelectable(gpAID(PKG), gpAID(X), gpAID(X), EnumSet.of(Privilege.ContactlessActivation), new byte[0]);
            var reg = gp.getRegistry();
            var x = reg.allApplets().stream().filter(e -> e.getAID().equals(gpAID(X))).findFirst()
                    .orElseThrow(() -> new AssertionError("X must be in the registry after successful INSTALL"));
            var crs = reg.allApplets().stream().filter(e -> e.getAID().equals(gpAID(CRS_AID))).findFirst()
                    .orElseThrow(() -> new AssertionError("Planted CRS must still be in the registry"));
            assertTrue(x.hasPrivilege(Privilege.ContactlessActivation));
            assertFalse(crs.hasPrivilege(Privilege.ContactlessActivation));
        }
        try (var bibo = simInstall.connect()) {
            var gp = openIsd(bibo);
            gp.installAndMakeSelectable(gpAID(PKG), gpAID(X2), gpAID(X2), EnumSet.of(Privilege.ContactlessSelfActivation), new byte[0]);
        }

        var simInitActivation = freshEngine();
        try (var bibo = simInitActivation.connect()) {
            var gp = openIsd(bibo);
            installCRELTestApplet(gp);
            installXWithParams(gp, buildEf(true, T));
        }
        try (var bibo = simInitActivation.connect()) {
            assertEquals(STATE_CL_ACTIVATED, findClStateInGetStatus(bibo, X));
        }
    }

    // INSTALL all-or-nothing edge cases: CREL dedup (GPC v2.3.1 Amd C 3.8.3), A4 remove-from-empty
    // no-op (3.8.4), empty A1 list, and parse-time rollback on a reserved activation byte.
    @Test
    public void installTransactionAndIdempotence() throws Exception {
        // 1. Duplicate CREL AID in A3 adds the target once, fires CREL_ADDED + SELECTABLE
        // (GPC v2.3.1 Amd C 3.8.3).
        var simDup = freshEngine();
        try (var bibo = simDup.connect()) {
            var gp = openIsd(bibo);
            installCRELTestApplet(gp);
            byte[] aidBytes = AIDUtil.bytes(T);
            TLV a3 = TLV.of(Tag.ber(0xA3),
                    TLV.of(Tag.ber(0x4F), aidBytes),
                    TLV.of(Tag.ber(0x4F), aidBytes));
            TLV efBlock = TLV.of(Tag.ber(0xEF), TLV.of(Tag.ber(0xA1), a3));
            installXWithParams(gp, efBlock);
        }
        try (var bibo = simDup.connect()) {
            var events = dumpCrelEvents(bibo);
            assertEquals(2, events.size());
            assertEvent(events.get(0), EVENT_CREL_ADDED, X);
            assertEvent(events.get(1), EVENT_SELECTABLE, X);
        }

        // 2. A4 remove against an empty list is silent no-op (GPC v2.3.1 Amd C 3.8.4); X installs
        // DEACTIVATED.
        var simA4 = freshEngine();
        try (var bibo = simA4.connect()) {
            var gp = openIsd(bibo);
            installCRELTestApplet(gp);
            byte[] aidBytes = AIDUtil.bytes(T);
            TLV efBlock = TLV.of(Tag.ber(0xEF),
                    TLV.of(Tag.ber(0xA1),
                            TLV.of(Tag.ber(0xA4),
                                    TLV.of(Tag.ber(0x4F), aidBytes))));
            installXWithParams(gp, efBlock);
        }
        try (var bibo = simA4.connect()) {
            var events = dumpCrelEvents(bibo);
            assertTrue(events.isEmpty());
        }
        try (var bibo = simA4.connect()) {
            assertEquals(STATE_CL_DEACTIVATED, findClStateInGetStatus(bibo, X));
        }

        // 3. Empty CREL list under A1 succeeds; no CREL registered, observer records nothing.
        var simEmpty = freshEngine();
        try (var bibo = simEmpty.connect()) {
            var gp = openIsd(bibo);
            installCRELTestApplet(gp);
            installXWithParams(gp, TLV.of(Tag.ber(0xEF), TLV.of(Tag.ber(0xA1), new byte[0])));
        }
        try (var bibo = simEmpty.connect()) {
            var events = dumpCrelEvents(bibo);
            assertTrue(events.isEmpty());
        }

        // 4. Reserved initial-activation byte (0x02, GPC v2.3.1 Amd C Table 11-3) is rejected at parse
        // BEFORE install commits: registry unchanged, no CREL events fan out (even with an A3
        // add-list present). SW=6A80 (GPC v2.3.1 Table 11-55).
        var simRollback = freshEngine();
        try (var bibo = simRollback.connect()) {
            var gp = openIsd(bibo);
            installCRELTestApplet(gp);
            TLV a3 = TLV.of(Tag.ber(0xA3), TLV.of(Tag.ber(0x4F), AIDUtil.bytes(T)));
            TLV a1 = TLV.of(Tag.ber(0xA1), a3);
            TLV a0 = TLV.of(Tag.ber(0xA0), TLV.of(Tag.ber(0x81), new byte[]{0x02}));
            TLV efBlock = TLV.of(Tag.ber(0xEF), a1, a0);
            var ex = assertThrows(GPException.class, () -> installXWithParams(gp, efBlock));
            assertEquals(0x6A80, ex.sw);
        }
        try (var bibo = simRollback.connect()) {
            selectAID(bibo, CRS_AID);
            byte[] body = getStatusAll(bibo);
            byte[] xBytes = AIDUtil.bytes(X);
            for (var entry : TLV.parse(body)) {
                var aidTlv = TLV.find(TLV.parse(entry.value()), Tag.ber(0x4F)).orElse(null);
                if (aidTlv != null) {
                    assertFalse(Arrays.equals(aidTlv.value(), xBytes));
                }
            }
        }
        try (var bibo = simRollback.connect()) {
            var events = dumpCrelEvents(bibo);
            assertTrue(events.isEmpty());
        }
    }

    // Single-holder privilege lifecycle (GPC v2.3.1 6.6.2): TRANSFER on INSTALL, RESTORE to ISD
    // on DELETE. Exercises FinalApplication; CardReset/ContactlessActivation share the plumbing.
    @Test
    public void finalApplicationLifecycle() throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        sim.loadApplet(PKG, X, GlobalPlatformTestApplet.class);

        // 1. Fresh card: the ISD holds FinalApplication by default (GPC v2.3.1 6.6.2).
        try (var bibo = sim.connect()) {
            var reg = openIsd(bibo).getRegistry();
            assertTrue(reg.getISD().orElseThrow().hasPrivilege(Privilege.FinalApplication));
        }

        // 2. INSTALL X with FinalApplication TRANSFERs the privilege from the ISD to X.
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            gp.installAndMakeSelectable(gpAID(PKG), gpAID(X), gpAID(X),
                    EnumSet.of(Privilege.FinalApplication), new byte[0]);
            var reg = gp.getRegistry();
            var x = reg.allApplets().stream().filter(e -> e.getAID().equals(gpAID(X))).findFirst()
                    .orElseThrow(() -> new AssertionError("X must be in the registry after INSTALL"));
            assertTrue(x.hasPrivilege(Privilege.FinalApplication));
            assertFalse(reg.getISD().orElseThrow().hasPrivilege(Privilege.FinalApplication));
        }

        // 3. DELETE X RESTORES FinalApplication to the ISD (GPC v2.3.1 6.6.2: returns on delete).
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            gp.deleteAID(gpAID(X), false);
            assertTrue(gp.getRegistry().getISD().orElseThrow().hasPrivilege(Privilege.FinalApplication));
        }
    }

    // Implicit CRS subscription + originator-suppress (GPC v2.3.1 Amd C 3.10.3/4), four engines:
    //   1. CRS receives EVENT_SELECTABLE for an unrelated applet (no per-applet CREL link).
    //   2. CRS does NOT receive an event it originated via cross-applet setCLState.
    //   3. CRS notified exactly once when also on the per-applet CREL list (dedupe).
    //   4. self-originated state change is not self-delivered (3.10.4).
    @Test
    public void crsImplicitSubscriptionAndOriginatorSuppress() throws Exception {
        // 1. Implicit subscription. CRSTestApplet at T with ContactlessActivation becomes the
        // effective CRS (TRANSFER, GPC v2.3.1 Amd C 7.1). X installs with NO CL params, so the
        // implicit-subscription path (3.10.3) is the only channel; exactly one event reaches T.
        // Fresh BIBO per phase: SELECTing T mid-session would break the next install.
        var sim1 = new JavaCardEngine.Builder().build();
        sim1.loadApplet(PKG, T, CRSTestApplet.class);
        sim1.loadApplet(PKG, X, GlobalPlatformTestApplet.class);
        try (var bibo = sim1.connect()) {
            var gp = openIsd(bibo);
            gp.installAndMakeSelectable(gpAID(PKG), gpAID(T), gpAID(T),
                    EnumSet.of(Privilege.ContactlessActivation, Privilege.GlobalRegistry), new byte[0]);
        }
        try (var bibo = sim1.connect()) {
            clearCrsLog(bibo);
        }
        try (var bibo = sim1.connect()) {
            var gp = openIsd(bibo);
            gp.installAndMakeSelectable(gpAID(PKG), gpAID(X), gpAID(X),
                    EnumSet.noneOf(Privilege.class), new byte[0]);
        }
        try (var bibo = sim1.connect()) {
            var events = dumpCrsEvents(bibo);
            assertEquals(1, events.size());
            assertEvent(events.get(0), EVENT_SELECTABLE, X);
        }

        // 2. Originator-suppress. CRS cross-activates X; as originator of EVENT_ACTIVATED it
        // receives no notification (GPC v2.3.1 Amd C 3.10.3).
        var sim2 = new JavaCardEngine.Builder().build();
        sim2.loadApplet(PKG, T, CRSTestApplet.class);
        sim2.loadApplet(PKG, X, GlobalPlatformTestApplet.class);
        try (var bibo = sim2.connect()) {
            var gp = openIsd(bibo);
            gp.installAndMakeSelectable(gpAID(PKG), gpAID(T), gpAID(T),
                    EnumSet.of(Privilege.ContactlessActivation, Privilege.GlobalRegistry), new byte[0]);
            gp.installAndMakeSelectable(gpAID(PKG), gpAID(X), gpAID(X),
                    EnumSet.noneOf(Privilege.class), new byte[0]);
        }
        try (var bibo = sim2.connect()) {
            clearCrsLog(bibo);
            var resp = bibo.transmit(new CommandAPDU(CREL_CLA, CREL_INS_DUMP,
                    (byte) 0x03, STATE_CL_ACTIVATED, AIDUtil.bytes(X)));
            assertEquals(0x9000, resp.getSW());
            assertEquals(STATE_CL_ACTIVATED, resp.getData()[0]);
            var dump = bibo.transmit(new CommandAPDU(CREL_CLA, CREL_INS_DUMP, CREL_P1_READ, 0x00, 256));
            assertEquals(0x9000, dump.getSW());
            // CRS must NOT receive notifications it originated.
            assertEquals(0, dump.getData().length);
        }

        // 3. Dedupe. X's CREL list names T (the CRS), so EVENT_SELECTABLE would reach T via both
        // per-applet fan-out (3.10.2) and implicit subscription (3.10.3); dispatcher collapses to
        // one. EVENT_CREL_ADDED rides notifyCRELListChange, unaffected, shows up once.
        var sim3 = new JavaCardEngine.Builder().build();
        sim3.loadApplet(PKG, T, CRSTestApplet.class);
        sim3.loadApplet(PKG, X, GlobalPlatformTestApplet.class);
        try (var bibo = sim3.connect()) {
            var gp = openIsd(bibo);
            gp.installAndMakeSelectable(gpAID(PKG), gpAID(T), gpAID(T),
                    EnumSet.of(Privilege.ContactlessActivation, Privilege.GlobalRegistry), new byte[0]);
        }
        try (var bibo = sim3.connect()) {
            clearCrsLog(bibo);
        }
        try (var bibo = sim3.connect()) {
            installXWithParams(openIsd(bibo), buildEf(false, T));
        }
        try (var bibo = sim3.connect()) {
            var events = dumpCrsEvents(bibo);
            // CRS on per-applet CREL list must NOT be double-notified for the same event.
            assertEquals(2, events.size());
            assertEvent(events.get(0), EVENT_CREL_ADDED, X);
            assertEvent(events.get(1), EVENT_SELECTABLE, X);
        }

        // 4. Self-originator suppress (GPC v2.3.1 Amd C 3.10.4). CRELTestApplet at T self-activates;
        // its own self-event log must NOT contain EVENT_ACTIVATED.
        var sim4 = new JavaCardEngine.Builder().build();
        sim4.loadApplet(PKG, T, CRELTestApplet.class);
        try (var bibo = sim4.connect()) {
            var gp = openIsd(bibo);
            gp.installAndMakeSelectable(gpAID(PKG), gpAID(T), gpAID(T),
                    EnumSet.of(Privilege.ContactlessSelfActivation), new byte[0]);
        }
        try (var bibo = sim4.connect()) {
            selectAID(bibo, T);
            // Clear both logs (drop the install-time EVENT_SELECTABLE).
            var clear = bibo.transmit(new CommandAPDU(CREL_CLA, CREL_INS_DUMP, (byte) 0x01, 0x00, 0));
            assertEquals(0x9000, clear.getSW());
            var self = bibo.transmit(new CommandAPDU(CREL_CLA, CREL_INS_DUMP,
                    CREL_P1_SELF_SETCLSTATE, STATE_CL_ACTIVATED, 256));
            assertEquals(0x9000, self.getSW());
            assertEquals(STATE_CL_ACTIVATED, self.getData()[0]);
            var selfLog = bibo.transmit(new CommandAPDU(CREL_CLA, CREL_INS_DUMP,
                    CREL_P1_READ_SELF, 0x00, 256));
            assertEquals(0x9000, selfLog.getSW());
            // Self-originated EVENT_ACTIVATED must NOT be self-delivered.
            assertEquals(0, selfLog.getData().length);
        }
    }

    // SELECT CRSTestApplet at T, dump and parse its event log; same record shape as dumpCrelEvents.
    private static List<byte[]> dumpCrsEvents(BIBO bibo) {
        selectAID(bibo, T);
        var dump = bibo.transmit(new CommandAPDU(CREL_CLA, CREL_INS_DUMP, CREL_P1_READ, 0x00, 256));
        assertEquals(0x9000, dump.getSW());
        byte[] data = dump.getData();
        var records = new ArrayList<byte[]>();
        int i = 0;
        while (i < data.length) {
            int aidLen = data[i + 2] & 0xFF;
            int recLen = 2 + 1 + aidLen + 1;
            assertEquals((byte) 0x01, data[i + recLen - 1]); // prev-null flag
            records.add(Arrays.copyOfRange(data, i, i + recLen));
            i += recLen;
        }
        return records;
    }

    // Clear the CRS log (P1=0x01). Caller MUST use a fresh BIBO with no active GP session.
    private static void clearCrsLog(BIBO bibo) {
        selectAID(bibo, T);
        var clear = bibo.transmit(new CommandAPDU(CREL_CLA, CREL_INS_DUMP, (byte) 0x01, 0x00, 0));
        assertEquals(0x9000, clear.getSW());
    }

    // ------------------- helpers ------------------- //

    // Fresh engine pre-loaded with both CRELTestApplet modules under a single PKG load file.
    private static JavaCardEngine freshEngine() {
        var sim = new JavaCardEngine.Builder().build();
        sim.loadApplet(PKG, T, CRELTestApplet.class);
        sim.loadApplet(PKG, X, CRELTestApplet.class);
        return sim;
    }

    // INSTALL CRELTestApplet at AID T with empty install params (no contactless TLVs).
    private static void installCRELTestApplet(GPSession gp) throws Exception {
        gp.installAndMakeSelectable(gpAID(PKG), gpAID(T), gpAID(T), EnumSet.noneOf(Privilege.class), new byte[0]);
    }

    // INSTALL host X with a (possibly empty) C9 block + caller-supplied EF block. Leading C9
    // stops GPSession.buildInstallData from re-wrapping the payload.
    private static void installXWithParams(GPSession gp, TLV efBlock) throws Exception {
        installAtAidWithParams(gp, X, efBlock);
    }

    // Generic install: instance AID == module AID, params = C9 (empty) || efBlock.
    private static void installAtAidWithParams(GPSession gp, AID instanceAid, TLV efBlock) throws Exception {
        byte[] combined = TLV.encode(TLV.of(Tag.ber(0xC9), new byte[]{0x00}), efBlock);
        gp.installAndMakeSelectable(gpAID(PKG), gpAID(instanceAid), gpAID(instanceAid), EnumSet.noneOf(Privilege.class), combined);
    }

    // Build EF { [A0 { 81 01 01 }], A1 { A3 { 4F <crelTarget> } } }. The A0 wrapper around the
    // initial-activation tag is mandatory (GPC v2.3.1 Amd C Table 11-3).
    private static TLV buildEf(boolean includeActivation, AID crelTarget) {
        TLV a1 = TLV.of(Tag.ber(0xA1), TLV.of(Tag.ber(0xA3), TLV.of(Tag.ber(0x4F), AIDUtil.bytes(crelTarget))));
        if (includeActivation) {
            TLV a0 = TLV.of(Tag.ber(0xA0), TLV.of(Tag.ber(0x81), new byte[]{0x01}));
            return TLV.of(Tag.ber(0xEF), a0, a1);
        }
        return TLV.of(Tag.ber(0xEF), a1);
    }

    // Encoded inner A5 proprietary template from a SELECT FCI; GET DATA must match it byte-for-byte.
    private static byte[] innerProprietaryBytes(byte[] fci) {
        var parsed = TLV.parse(fci);
        assertEquals(1, parsed.size());
        var children = TLV.parse(parsed.get(0).value());
        var proprietary = TLV.find(children, Tag.ber(0xA5))
                .orElseThrow(() -> new AssertionError("FCI must carry tag A5"));
        return proprietary.encode();
    }

    // GET DATA over the current selection; decode the 2-byte big-endian update counter.
    private static int readGetDataCounter(BIBO bibo) {
        var resp = bibo.transmit(new CommandAPDU(CRS_CLA, INS_GET_DATA, P1_GET_DATA, P2_GET_DATA, 256));
        assertEquals(0x9000, resp.getSW());
        var parsed = TLV.parse(resp.getData());
        var inner = TLV.parse(parsed.get(0).value());
        byte[] counter = TLV.find(inner, Tag.ber(0x80))
                .orElseThrow(() -> new AssertionError("80 missing from GET DATA body")).value();
        assertEquals(2, counter.length);
        return ((counter[0] & 0xFF) << 8) | (counter[1] & 0xFF);
    }

    // Validate SELECT CRS FCI shape (GPC v2.3.1 Amd C Table 3-30) and return the counter bytes.
    private static byte[] parseUpdateCounter(byte[] fci) {
        var parsed = TLV.parse(fci);
        assertEquals(1, parsed.size());
        var template = parsed.get(0);
        assertEquals(Tag.ber(0x6F), template.tag());
        var children = TLV.parse(template.value());
        var aidTlv = TLV.find(children, Tag.ber(0x84)).orElseThrow(() -> new AssertionError("FCI must carry tag 84 (AID)"));
        assertArrayEquals(AIDUtil.bytes(CRS_AID), aidTlv.value());
        var proprietary = TLV.find(children, Tag.ber(0xA5)).orElseThrow(() -> new AssertionError("FCI must carry tag A5 (proprietary template)"));
        var inner = TLV.parse(proprietary.value());
        var versionTlv = TLV.find(inner, Tag.ber(0x9F08)).orElseThrow(() -> new AssertionError("A5 must carry tag 9F08 (version)"));
        assertArrayEquals(new byte[]{0x01, 0x00}, versionTlv.value());
        var counterTlv = TLV.find(inner, Tag.ber(0x80)).orElseThrow(() -> new AssertionError("A5 must carry tag 80 (Global Update Counter)"));
        return counterTlv.value();
    }

    // Send raw SELECT-by-AID and return the response data (FCI). Asserts SW=9000.
    private static byte[] selectAID(BIBO bibo, AID aid) {
        var r = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AIDUtil.bytes(aid), 256));
        assertEquals(0x9000, r.getSW());
        return r.getData();
    }

    // SELECT CRELTestApplet at T, dump its CREL event ring, return raw records. Layout:
    // event-hi | event-lo | aid-len | aid bytes | prev-null-flag (asserted inline).
    private static List<byte[]> dumpCrelEvents(BIBO bibo) {
        selectAID(bibo, T);
        var dump = bibo.transmit(new CommandAPDU(CREL_CLA, CREL_INS_DUMP, CREL_P1_READ, 0x00, 256));
        assertEquals(0x9000, dump.getSW());
        byte[] data = dump.getData();
        var records = new ArrayList<byte[]>();
        int i = 0;
        while (i < data.length) {
            int aidLen = data[i + 2] & 0xFF;
            int recLen = 2 + 1 + aidLen + 1;
            assertEquals((byte) 0x01, data[i + recLen - 1]); // prev-null flag
            records.add(Arrays.copyOfRange(data, i, i + recLen));
            i += recLen;
        }
        return records;
    }

    private static short eventOf(byte[] rec) {
        return (short) (((rec[0] & 0xFF) << 8) | (rec[1] & 0xFF));
    }

    private static AID targetOf(byte[] rec) {
        int aidLen = rec[2] & 0xFF;
        return aidLen == 0 ? null : AIDUtil.create(Arrays.copyOfRange(rec, 3, 3 + aidLen));
    }

    // GET STATUS with the '4F 00' match-all filter, reassembling 6310 continuations.
    // Caller must have already SELECTed the CRS.
    private static byte[] getStatusAll(BIBO bibo) {
        byte[] data = TLV.of(Tag.ber(0x4F), new byte[0]).encode();
        var resp = bibo.transmit(new CommandAPDU(CRS_CLA, INS_GET_STATUS, P1_GET_APPLICATIONS, 0x00, data, 256));
        var assembled = new ByteArrayOutputStream();
        assembled.writeBytes(resp.getData());
        while (resp.getSW() == 0x6310) {
            resp = bibo.transmit(new CommandAPDU(CRS_CLA, INS_GET_STATUS, P1_GET_APPLICATIONS, 0x01, data, 256));
            assembled.writeBytes(resp.getData());
        }
        assertEquals(0x9000, resp.getSW());
        return assembled.toByteArray();
    }

    // Find the given AID's GET STATUS entry; return its clState byte (2nd byte of 9F70).
    private static byte findClStateInGetStatus(BIBO bibo, AID target) {
        selectAID(bibo, CRS_AID);
        byte[] body = getStatusAll(bibo);
        var entries = TLV.parse(body);
        byte[] targetBytes = AIDUtil.bytes(target);
        for (var entry : entries) {
            assertEquals(Tag.ber(0x61), entry.tag());
            var children = TLV.parse(entry.value());
            var aidTlv = TLV.find(children, Tag.ber(0x4F)).orElse(null);
            if (aidTlv == null) {
                continue;
            }
            if (!Arrays.equals(aidTlv.value(), targetBytes)) {
                continue;
            }
            var stateTlv = TLV.find(children, Tag.ber(0x9F70)).orElseThrow(() -> new AssertionError("9F70 missing from 61 record"));
            byte[] v = stateTlv.value();
            // 9F70 must be 2 bytes (lifecycle + clState).
            assertEquals(2, v.length);
            return v[1];
        }
        throw new AssertionError("GET STATUS did not return an entry for " + target);
    }

    // Assert a recorded CREL event matches the expected event short and target AID.
    private static void assertEvent(byte[] rec, short expectedEvent, AID expectedTarget) {
        assertEquals(expectedEvent, eventOf(rec));
        var target = targetOf(rec);
        assertNotNull(target);
        assertEquals(expectedTarget, target);
    }

}
