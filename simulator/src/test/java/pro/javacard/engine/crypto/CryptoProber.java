// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.crypto;

import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import javacard.framework.JCSystem;

// Driver over apdu4j.core.BIBO for CryptoProbeApplet. One method per INS; each builds the wire
// body, transmits over the given BIBO (in-process engine or a PC/SC reader), and returns the
// applet result. Transport SW is always 9000; the meaningful status is the leading response byte
// (0x00 ok, else a CryptoException reason, else 0xFF).
public final class CryptoProber {

    public static final int INS_NEW_KEY = 0x10;
    public static final int INS_NEW_KEY_SHARED = 0x11;
    public static final int INS_SET_COMPONENT = 0x20;
    public static final int INS_GET_COMPONENT = 0x21;
    public static final int INS_GEN_KEYPAIR = 0x30;
    public static final int INS_DIGEST = 0x40;
    public static final int INS_CIPHER = 0x50;
    public static final int INS_SIGN = 0x60;
    public static final int INS_VERIFY = 0x61;
    public static final int INS_KEYAGREEMENT = 0x70;
    public static final int INS_MEMORY = 0x80;

    public static final int COMP_A = 1;
    public static final int COMP_B = 2;
    public static final int COMP_G = 3;
    public static final int COMP_R = 4;
    public static final int COMP_FIELD_FP = 5;
    public static final int COMP_K = 6;
    public static final int COMP_S = 7;
    public static final int COMP_W = 8;
    public static final int COMP_SYMMETRIC = 9;
    public static final int COMP_RSA_MOD = 10;
    public static final int COMP_RSA_EXP = 11;
    public static final int COMP_RSA_PRIVEXP = 12;
    public static final int COMP_P = 13;
    public static final int COMP_Q = 14;
    public static final int COMP_DP = 15;
    public static final int COMP_DQ = 16;
    public static final int COMP_PQ = 17;

    public static final int MODE_ENCRYPT = 0x01;
    public static final int MODE_DECRYPT = 0x02;

    public static final int OUTCOME_SUCCESS = 0x00;
    public static final int OUTCOME_EXCEPTION = 0x01;

    // Exception type ids reported in an EXCEPTION outcome.
    public static final int EXC_CRYPTO = 1;

    // CryptoException reason codes.
    public static final int CRYPTO_ILLEGAL_VALUE = 1;
    public static final int CRYPTO_NO_SUCH_ALGORITHM = 3;

    // Extended-length ne; short-form ne=256 would truncate RSA-2048 key components.
    private static final int NE_MAX = 65536;

    private final BIBO bibo;

    public CryptoProber(BIBO bibo) {
        this.bibo = bibo;
    }

    // Decoded response: SUCCESS carries retCode and output bytes; EXCEPTION carries excType + reason.
    public record Result(int outcome, int excType, int reason, int retCode, byte[] output) {
        public boolean ok() {
            return outcome == OUTCOME_SUCCESS;
        }

        public boolean isCrypto(int wantReason) {
            return outcome == OUTCOME_EXCEPTION && excType == EXC_CRYPTO && reason == wantReason;
        }

        public boolean noSuchAlgorithm() {
            return isCrypto(CRYPTO_NO_SUCH_ALGORITHM);
        }

        public boolean illegalValue() {
            return isCrypto(CRYPTO_ILLEGAL_VALUE);
        }
    }

    public void select(byte[] aid) {
        ResponseAPDU r = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid, 256));
        if (r.getSW() != 0x9000) {
            throw new IllegalStateException("SELECT failed: %04X".formatted(r.getSW()));
        }
    }

    public Result newKey(int slot, int memType, int keyConst, int len) {
        byte[] data = {(byte) memType, (byte) keyConst, (byte) (len >> 8), (byte) len};
        return send(INS_NEW_KEY, slot, 0, data);
    }

    public Result newKeyShared(int slot, int domainSlot, int algType) {
        byte[] data = {(byte) algType};
        return send(INS_NEW_KEY_SHARED, slot, domainSlot, data);
    }

    public Result setComponent(int slot, int compId, byte[] data) {
        return send(INS_SET_COMPONENT, slot, compId, data);
    }

    public Result getComponent(int slot, int compId) {
        return send(INS_GET_COMPONENT, slot, compId, null);
    }

    public Result genKeyPair(int pubSlot, int privSlot) {
        return send(INS_GEN_KEYPAIR, pubSlot, privSlot, null);
    }

    public Result digest(int alg, byte[] input) {
        return send(INS_DIGEST, alg & 0xFF, 0, input);
    }

    public Result cipher(int alg, int mode, int keySlot, byte[] iv, byte[] input) {
        var body = new ByteArrayOutputStream();
        body.write(keySlot & 0xFF);
        byte[] ivb = iv == null ? new byte[0] : iv;
        body.write(ivb.length & 0xFF);
        body.writeBytes(ivb);
        body.writeBytes(input);
        return send(INS_CIPHER, alg & 0xFF, mode, body.toByteArray());
    }

    public Result sign(int alg, int keySlot, byte[] msg) {
        return send(INS_SIGN, alg & 0xFF, keySlot, msg);
    }

    public Result verify(int alg, int keySlot, byte[] sig, byte[] msg) {
        var body = new ByteArrayOutputStream();
        body.write((sig.length >> 8) & 0xFF);
        body.write(sig.length & 0xFF);
        body.writeBytes(sig);
        body.writeBytes(msg);
        return send(INS_VERIFY, alg & 0xFF, keySlot, body.toByteArray());
    }

    public Result keyAgreement(int alg, int privSlot, byte[] pubW) {
        return send(INS_KEYAGREEMENT, alg & 0xFF, privSlot, pubW);
    }

    // Returns 12 bytes: 32-bit free-memory counts for persistent, transient-reset, and transient-deselect pools.
    public Result memory() {
        return send(INS_MEMORY, 0x00, 0, null);
    }

    // Triggers object deletion; retCode is 1 if the card supports it, 0 otherwise.
    public Result gc() {
        return send(INS_MEMORY, 0x01, 0, null);
    }

    // Tries a transient (DESELECT) key in both KeyBuilder spellings; on any non-success outcome retries
    // with a persistent key of the same length. A build that fails leaves the slot holding the earlier key.
    public Result newKeyWithFallback(int slot, int algType, int deselectType, int persistentType, int len) {
        Result byKeyType = newKey(slot, 0, deselectType, len);
        Result byMemoryType = newKey(slot, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, algType, len);
        if (byMemoryType.ok()) {
            return byMemoryType;
        }
        if (byKeyType.ok()) {
            return byKeyType;
        }
        return newKey(slot, 0, persistentType, len);
    }

    private Result send(int ins, int p1, int p2, byte[] data) {
        var cmd = data == null || data.length == 0
                ? new CommandAPDU(0x80, ins, p1, p2, NE_MAX)
                : new CommandAPDU(0x80, ins, p1, p2, data, NE_MAX);
        ResponseAPDU r = bibo.transmit(cmd);
        if (r.getSW() != 0x9000) {
            throw new IllegalStateException("INS 0x%02X failed: %04X".formatted(ins, r.getSW()));
        }
        byte[] body = r.getData();
        if (body.length == 0) {
            throw new IllegalStateException("INS 0x%02X returned empty body".formatted(ins));
        }
        int outcome = body[0] & 0xFF;
        if (outcome == OUTCOME_EXCEPTION) {
            if (body.length < 4) {
                throw new IllegalStateException("INS 0x%02X truncated exception body".formatted(ins));
            }
            int excType = body[1] & 0xFF;
            int reason = ((body[2] & 0xFF) << 8) | (body[3] & 0xFF);
            return new Result(outcome, excType, reason, 0, new byte[0]);
        }
        if (body.length < 3) {
            throw new IllegalStateException("INS 0x%02X truncated success body".formatted(ins));
        }
        int retCode = ((body[1] & 0xFF) << 8) | (body[2] & 0xFF);
        return new Result(outcome, 0, 0, retCode, Arrays.copyOfRange(body, 3, body.length));
    }
}
