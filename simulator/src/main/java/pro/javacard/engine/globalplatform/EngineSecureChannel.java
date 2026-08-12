// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.globalplatform.SecureChannel;
import pro.javacard.gp.GPUtils;
import pro.javacard.gp.keys.PlaintextKeys;

import java.util.Arrays;
import java.util.Objects;

// Internal base for the SCP02/SCP03 secure channel impls. Holds the shared session
// state (security level, session keys) and centralizes the reset/auth-check sequences.
public abstract sealed class EngineSecureChannel implements SecureChannel permits SCP02SecureChannel, SCP03SecureChannel {

    protected byte state = NO_SECURITY_LEVEL;
    protected byte[] macKey;
    protected byte[] encKey;

    // A session that was aborted keeps rejecting commands until it is terminated (GPC v2.3.1 10.2.3);
    // this is what separates "no session" (unwrap passes the command through) from an aborted one.
    protected boolean aborted;

    // Master key set for the active session. Resolved at INITIALIZE UPDATE by initializeMasterKey(),
    // cleared by resetSecurity() (power cycle, applet deselect, explicit drop). Read to derive session
    // keys and by SCP03.decryptData() for static-DEK operations.
    protected KeySet currentMasterKey;

    // GP INS values processed by processSecurity().
    static final byte INS_INITIALIZE_UPDATE = (byte) 0x50;
    static final byte INS_EXTERNAL_AUTHENTICATE = (byte) 0x82;

    @Override
    public final byte getSecurityLevel() {
        return state;
    }

    // INITIALIZE UPDATE master-key initialization. The secure channel does not contain the key-lookup
    // walk - that belongs to the SD applet (resolveKeySet). The channel only supplies what it knows:
    // the calling applet context and the requested key version (IU P1). The resolved set is this SD's
    // own keys or, failing that, its parent SD's (GPC v2.3.1 7.1).
    protected final PlaintextKeys initializeMasterKey(byte requestedKvn) {
        var ks = SecurityDomainApplet.resolveKeySet(Simulator.current().currentApplication(), requestedKvn);
        if (ks.isEmpty()) {
            ISOException.throwIt(requestedKvn == 0 ? ISO7816.SW_CONDITIONS_NOT_SATISFIED : ISO7816.SW_INCORRECT_P1P2);
        }
        currentMasterKey = ks.get();
        return PlaintextKeys.fromKeys(currentMasterKey.value(KeySet.KID_ENC), currentMasterKey.value(KeySet.KID_MAC), currentMasterKey.value(KeySet.KID_DEK));
    }

    // Terminate the session: drop authentication, master keys and the aborted condition, let the SCP
    // impl wipe its own state. Called externally (resetSecurity contract): power cycle, deliberate drop.
    @Override
    public final void resetSecurity() {
        resetSession();
        currentMasterKey = null;
    }

    // Internal session-only reset: used by SCP impls at INITIALIZE UPDATE start, which terminates any
    // previous session (SCP03 Amd D v1.2 5.6). The master key set is re-resolved by the same
    // INITIALIZE UPDATE; ssc deliberately persists across.
    protected final void resetSession() {
        abort();
        aborted = false;
    }

    // Abort without terminating: the security level drops but the error condition sticks until the
    // session is terminated (GPC v2.3.1 10.2.3). Used on every failed cryptographic verification.
    protected final void abort() {
        state = NO_SECURITY_LEVEL;
        aborted = true;
        wipeScpState();
        // Dropping the session keys, not just their content, is what makes the "a successful execution
        // of the INITIALIZE UPDATE command shall precede this command" check on EXTERNAL AUTHENTICATE
        // work (GPC v2.3.1 E.5.2.1): zeroed-but-present keys would authenticate under an all-zero key.
        macKey = null;
        encKey = null;
    }

    // Throws SW_CONDITIONS_NOT_SATISFIED if no Secure Channel Session is open.
    protected final void requireAuthenticated() {
        if ((state & AUTHENTICATED) == 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    // Reading an incoming command outside baBuffer is an ArrayIndexOutOfBoundsException per the
    // SecureChannel contract, which Arrays.copyOfRange would otherwise mask by zero-filling the
    // missing tail. Throws NullPointerException for a null buffer, as the same contract requires.
    protected static void checkBounds(byte[] baBuffer, short sOffset, short sLength) {
        if (sOffset < 0 || sLength < 0 || sOffset + sLength > baBuffer.length) {
            throw new ArrayIndexOutOfBoundsException(sOffset + sLength);
        }
    }

    // Reject with 6985 while an aborted session has not been terminated.
    protected final void rejectIfAborted() {
        if (state == NO_SECURITY_LEVEL && aborted) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    // SecureChannel.processSecurity answers 6E00 for a class byte it does not recognize, leaving 6D00
    // to the instruction dispatch. INITIALIZE UPDATE is 80, EXTERNAL AUTHENTICATE is 84.
    protected static void checkCLA(byte cla) {
        if (cla != (byte) 0x80 && cla != (byte) 0x84) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    // EXTERNAL AUTHENTICATE security levels: GPC v2.3.1 Table E-11 and SCP03 Amd D v1.2 Table 7-6
    // minus every row setting R-MAC or R-ENCRYPTION, which wrap() cannot honor.
    protected static void checkSecurityLevel(byte p1) {
        if (p1 != NO_SECURITY_LEVEL && p1 != C_MAC && p1 != (C_MAC | C_DECRYPTION)) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    // Only the pass-through path exists while response protection is unimplemented: no security level
    // requiring it can be negotiated, so wrap() just removes the status bytes the application appended.
    @Override
    public final short wrap(byte[] baBuffer, short sOffset, short sLength) throws ISOException {
        Objects.requireNonNull(baBuffer);
        rejectIfAborted();
        // Without the status bytes the application is required to append there is nothing to wrap.
        if (sLength < 2) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        return (short) (sLength - 2);
    }

    // No sensitive data encryption mechanism is defined here; the interface reserves 6982 for that.
    @Override
    public final short encryptData(byte[] baBuffer, short sOffset, short sLength) throws ISOException {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        return 0;
    }

    // Null-safe varargs zeroize helper for use inside wipeScpState().
    protected static void zeroize(byte[]... arrays) {
        for (var a : arrays) {
            if (a != null) {
                Arrays.fill(a, (byte) 0);
            }
        }
    }

    // Unwrap a command reassembled from GP command-chaining chunks (GPC v2.3.1 11.1.5.1), returning
    // its plaintext payload. The C-MAC covers the full reassembled command, so MAC verification
    // runs once over the concatenated chunk data, not per chunk.
    public abstract byte[] unwrapReassembled(byte cla, byte ins, byte p1, byte p2, byte[] wrapped);

    // Max plaintext response payload that fits in a 256-byte APDU response after wrap().
    abstract short maxResponseLength();

    // SCP-specific cleanup: zero session keys + per-SCP crypto buffers (ICV, chaining, ...).
    protected abstract void wipeScpState();

    // Zero the SCP sequence counter. GPC v2.3.1 E.1.2: reset on creation or update of the SC keys.
    abstract void resetCounter();

    // KDD = last 2 bytes of the currently selected AID || CPLC bytes 10..17
    // (IC fab date || IC SN || IC batch ID). Mirrors how off-card tooling derives KDD
    // from the card's CPLC. Used by SCP02/SCP03 INITIALIZE_UPDATE.
    protected static byte[] sessionKDD() {
        var sim = Simulator.current();
        byte[] cplc = sim.gp().isd().getData(GPData.CPLC);
        byte[] aidBytes = AIDUtil.bytes(sim.getAID());
        byte[] aidTail = Arrays.copyOfRange(aidBytes, aidBytes.length - 2, aidBytes.length);
        return GPUtils.concatenate(aidTail, Arrays.copyOfRange(cplc, 10, 18));
    }
}
