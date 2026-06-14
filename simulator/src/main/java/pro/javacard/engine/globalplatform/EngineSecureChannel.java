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

// Internal base for the SCP02/SCP03 secure channel impls. Holds the shared session
// state (security level, session keys) and centralizes the reset/auth-check sequences.
public abstract sealed class EngineSecureChannel implements SecureChannel permits SCP02SecureChannel, SCP03SecureChannel {

    protected byte state = NO_SECURITY_LEVEL;
    protected byte[] macKey;
    protected byte[] encKey;

    // Master key set for the active session. Resolved at INITIALIZE UPDATE by initializeMasterKey(),
    // cleared by resetSecurity() (power cycle / MAC failure / explicit drop). Read to derive session
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
        var ks = SecurityDomainApplet.resolveKeySet(Simulator.current().caller(), requestedKvn);
        if (ks.isEmpty()) {
            ISOException.throwIt(requestedKvn == 0 ? ISO7816.SW_CONDITIONS_NOT_SATISFIED : ISO7816.SW_INCORRECT_P1P2);
        }
        currentMasterKey = ks.get();
        return PlaintextKeys.fromKeys(currentMasterKey.value(KeySet.KID_ENC), currentMasterKey.value(KeySet.KID_MAC), currentMasterKey.value(KeySet.KID_DEK));
    }

    // Drop authentication and master keys, let the SCP impl wipe its own session state.
    // Called externally (resetSecurity contract): power cycle, MAC failure, deliberate drop.
    @Override
    public final void resetSecurity() {
        state = NO_SECURITY_LEVEL;
        wipeScpState();
        currentMasterKey = null;
    }

    // Internal session-only reset: used by SCP impls at INITIALIZE UPDATE start to clear the previous
    // session's session keys. The master key set is re-resolved by the same INITIALIZE UPDATE; ssc
    // deliberately persists across.
    protected final void resetSession() {
        state = NO_SECURITY_LEVEL;
        wipeScpState();
    }

    // Throws SW_CONDITIONS_NOT_SATISFIED if the channel is not in AUTHENTICATED state.
    protected final void requireAuthenticated() {
        if ((state & AUTHENTICATED) == 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    // Null-safe varargs zeroize helper for use inside wipeScpState().
    protected static void zeroize(byte[]... arrays) {
        for (var a : arrays) {
            if (a != null) {
                Arrays.fill(a, (byte) 0);
            }
        }
    }

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
