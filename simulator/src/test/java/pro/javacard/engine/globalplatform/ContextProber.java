// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.HexUtils;
import apdu4j.core.ResponseAPDU;

import java.util.Arrays;

// Driver over apdu4j.core.BIBO for ContextProbeApplet. Selects the applet, reads back the probe
// results it recorded during install() and during a forwarded STORE DATA, and runs the baseline
// that repeats the same operations while the applet itself is selected.
// The same class drives the in-process engine and a PC/SC reader; nothing here reaches into engine
// internals. The slot layout and the marker values mirror the applet, which must stay self-contained
// to compile to a CAP.
public final class ContextProber {

    public static final int INS_READ = 0x10;
    public static final int INS_TOUCH = 0x11;

    // Probe outcomes.
    public static final int OUT_OK = 0x00;
    public static final int OUT_SECURITY = 0x01;
    public static final int OUT_SYSTEM = 0x02;
    public static final int OUT_OTHER = 0x03;
    public static final int NOT_RUN = 0xFF;

    // javacard.framework.SystemException.ILLEGAL_TRANSIENT
    public static final int ILLEGAL_TRANSIENT = 3;

    // Install-time getAID() verdict.
    public static final int AID_NULL = 0;
    public static final int AID_INSTANCE = 1;
    public static final int AID_OTHER = 2;

    // Whether an OPEN service handed back an object or null.
    public static final int ABSENT = 0;
    public static final int PRESENT = 1;

    // Step markers. The applet writes one to slot 0 before attempting the probe it names, so a
    // runtime that kills the applet instead of throwing leaves behind the marker of the probe that
    // did it. STEP_PERSO_DONE means every processData() probe was attempted and returned.
    public static final int STEP_CTOR_GP = 0x10;
    public static final int STEP_CTOR_COD = 0x11;
    public static final int STEP_INSTALL_AID = 0x12;
    public static final int STEP_INSTALL_COD = 0x13;
    public static final int STEP_PERSO_READ = 0x21;
    public static final int STEP_PERSO_WRITE = 0x22;
    public static final int STEP_PERSO_COPY = 0x23;
    public static final int STEP_PERSO_MAKE = 0x24;
    public static final int STEP_PERSO_AIDS = 0x25;
    public static final int STEP_PERSO_DONE = 0x2F;

    private static final int RESULTS_LEN = 80;

    private static final int SLOT_STEP = 0;
    private static final int SLOT_CTOR_COD = 1;
    private static final int SLOT_COD_REAL = 4;
    private static final int SLOT_INSTALL_AID = 5;
    private static final int SLOT_INSTALL_COD = 6;
    private static final int SLOT_PERSO_READ = 9;
    private static final int SLOT_PERSO_WRITE = 12;
    private static final int SLOT_PERSO_COPY = 15;
    private static final int SLOT_PERSO_MAKE = 18;
    private static final int SLOT_PERSO_AID = 21;
    private static final int SLOT_PERSO_PREV = 38;
    private static final int SLOT_INSTALL_AID_BYTES = 55;
    private static final int SLOT_PRE_GP = 72;
    private static final int SLOT_PRE_ENTRY = 75;
    private static final int SLOT_PRE_CVM = 76;
    private static final int SLOT_PRE_SC = 77;
    private static final int SLOT_PRE_STATE = 78;
    private static final int SLOT_POST_ENTRY = 79;

    private final BIBO bibo;

    public ContextProber(BIBO bibo) {
        this.bibo = bibo;
    }

    // One probe: the outcome byte and, for a SystemException, its reason code.
    public record Probe(int outcome, int reason) {
        public boolean ok() {
            return outcome == OUT_OK;
        }

        public boolean security() {
            return outcome == OUT_SECURITY;
        }

        public boolean system(int wantReason) {
            return outcome == OUT_SYSTEM && reason == wantReason;
        }

        @Override
        public String toString() {
            return switch (outcome) {
                case OUT_OK -> "ok";
                case OUT_SECURITY -> "SecurityException";
                case OUT_SYSTEM -> "SystemException(%d)".formatted(reason);
                case OUT_OTHER -> "other exception";
                case NOT_RUN -> "not run";
                default -> "unknown outcome %02X".formatted(outcome);
            };
        }
    }

    // The whole recorded truth table plus the applet's own AID readings during processData().
    public record Results(int step, Probe preGP, int preEntry, int preCVM, int preSecureChannel, int preState, int postEntry,
                          Probe ctorCod, boolean codIsTransient, int installAid, byte[] installAIDBytes, Probe installCod,
                          Probe persoRead, Probe persoWrite, Probe persoCopy, Probe persoMake,
                          byte[] persoAID, byte[] persoPrevAID) {

        public String table() {
            return """
                    step marker          : %s
                    pre-register OPEN    : %s
                    pre-register entry   : %s
                    pre-register CVM     : %s
                    pre-register channel : %s
                    pre-register LCS     : 0x%02X
                    post-register entry  : %s
                    install ctor COD     : %s (array is %s)
                    install getAID()     : %s = %s
                    install make COD     : %s
                    perso read COD       : %s
                    perso write COD      : %s
                    perso arrayCopy COD  : %s
                    perso make COD       : %s
                    perso getAID()       : %s
                    perso prevContextAID : %s"""
                    .formatted(stepName(step), preGP, presence(preEntry), presence(preCVM), presence(preSecureChannel), preState,
                            presence(postEntry), ctorCod, codIsTransient ? "CLEAR_ON_DESELECT" : "a persistent fallback",
                            aidVerdict(installAid), aid(installAIDBytes), installCod, persoRead, persoWrite, persoCopy, persoMake,
                            aid(persoAID), aid(persoPrevAID));
        }

        private static String aid(byte[] v) {
            return v.length == 0 ? "null" : HexUtils.bin2hex(v);
        }

        private static String presence(int code) {
            return switch (code) {
                case ABSENT -> "null";
                case PRESENT -> "an object";
                default -> "not run";
            };
        }
    }

    public void select(byte[] aid) {
        ResponseAPDU r = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid, 256));
        if (r.getSW() != 0x9000) {
            throw new IllegalStateException("SELECT failed: %04X".formatted(r.getSW()));
        }
    }

    public Results read() {
        byte[] body = send(INS_READ);
        if (body.length != RESULTS_LEN) {
            throw new IllegalStateException("results length %d, want %d".formatted(body.length, RESULTS_LEN));
        }
        return new Results(body[SLOT_STEP] & 0xFF,
                probe(body, SLOT_PRE_GP),
                body[SLOT_PRE_ENTRY] & 0xFF,
                body[SLOT_PRE_CVM] & 0xFF,
                body[SLOT_PRE_SC] & 0xFF,
                body[SLOT_PRE_STATE] & 0xFF,
                body[SLOT_POST_ENTRY] & 0xFF,
                probe(body, SLOT_CTOR_COD),
                body[SLOT_COD_REAL] == 1,
                body[SLOT_INSTALL_AID] & 0xFF,
                aidAt(body, SLOT_INSTALL_AID_BYTES),
                probe(body, SLOT_INSTALL_COD),
                probe(body, SLOT_PERSO_READ),
                probe(body, SLOT_PERSO_WRITE),
                probe(body, SLOT_PERSO_COPY),
                probe(body, SLOT_PERSO_MAKE),
                aidAt(body, SLOT_PERSO_AID),
                aidAt(body, SLOT_PERSO_PREV));
    }

    // Baseline run of the same operations with the applet selected.
    public Probe touch() {
        byte[] body = send(INS_TOUCH);
        if (body.length != 3) {
            throw new IllegalStateException("touch length %d, want 3".formatted(body.length));
        }
        return probe(body, 0);
    }

    private byte[] send(int ins) {
        ResponseAPDU r = bibo.transmit(new CommandAPDU(0x80, ins, 0x00, 0x00, 256));
        if (r.getSW() != 0x9000) {
            throw new IllegalStateException("INS 0x%02X failed: %04X".formatted(ins, r.getSW()));
        }
        return r.getData();
    }

    private static Probe probe(byte[] body, int slot) {
        return new Probe(body[slot] & 0xFF, ((body[slot + 1] & 0xFF) << 8) | (body[slot + 2] & 0xFF));
    }

    private static byte[] aidAt(byte[] body, int slot) {
        int len = body[slot] & 0xFF;
        return Arrays.copyOfRange(body, slot + 1, slot + 1 + len);
    }

    private static String aidVerdict(int code) {
        return switch (code) {
            case AID_NULL -> "null";
            case AID_INSTANCE -> "the instance AID";
            case AID_OTHER -> "some other AID";
            default -> "not run";
        };
    }

    private static String stepName(int step) {
        return switch (step) {
            case STEP_CTOR_GP -> "constructor OPEN services";
            case STEP_CTOR_COD -> "constructor COD allocation";
            case STEP_INSTALL_AID -> "install getAID()";
            case STEP_INSTALL_COD -> "install COD allocation";
            case STEP_PERSO_READ -> "perso COD read";
            case STEP_PERSO_WRITE -> "perso COD write";
            case STEP_PERSO_COPY -> "perso COD arrayCopy";
            case STEP_PERSO_MAKE -> "perso COD allocation";
            case STEP_PERSO_AIDS -> "perso AID capture";
            case STEP_PERSO_DONE -> "all perso probes returned";
            default -> "unknown marker %02X".formatted(step);
        };
    }
}
