// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.globalplatform.SecureChannel;
import pro.javacard.gp.GPUtils;

import java.util.Arrays;

// Internal base for the SCP02/SCP03 secure channel impls. Holds the shared session
// state (security level, session keys) and centralizes the reset/auth-check sequences.
public abstract sealed class EngineSecureChannel implements SecureChannel permits SCP02SecureChannelImpl, SCP03SecureChannelImpl {

    protected byte state = NO_SECURITY_LEVEL;
    protected byte[] macKey;
    protected byte[] encKey;

    // Master keys for the active session. Set by beginSession() at INITIALIZE_UPDATE time,
    // cleared by resetSecurity() (power cycle / MAC failure / explicit drop). Read by processSecurity()
    // to derive session keys, and by SCP03.decryptData() for static-DEK operations.
    protected KeySet currentMasterKey;

    // GP INS values processed by processSecurity().
    static final byte INS_INITIALIZE_UPDATE     = (byte) 0x50;
    static final byte INS_EXTERNAL_AUTHENTICATE = (byte) 0x82;

    @Override
    public final byte getSecurityLevel() {
        return state;
    }

    // Prime master keys for the upcoming session. Called by the OPEN before processSecurity()
    // at INITIALIZE_UPDATE time. The keys persist for the session lifetime.
    public final void beginSession(KeySet keys) {
        this.currentMasterKey = keys;
    }

    // Resolve the master key set for this session. If the OPEN already primed via beginSession()
    // (the normal path), return that. Otherwise delegate to SecurityDomainApplet.resolveKeys(),
    // which walks the SD chain and returns the first non-empty own keyset; we pick its newest.
    //
    // Stashes the resolved keys in currentMasterKey for later session use (decryptData, etc.).
    protected final KeySet resolveMasterKey() {
        if (currentMasterKey != null) {
            return currentMasterKey;
        }
        var sim = Simulator.current();
        var ks = SecurityDomainApplet.resolveKeys(sim, sim.lookupApplet(sim.getAID()))
                .stream().reduce((a, b) -> b).orElse(null);
        if (ks == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        currentMasterKey = ks;
        return ks;
    }

    // Drop authentication and master keys, let the SCP impl wipe its own session state.
    // Called externally (resetSecurity contract): power cycle, MAC failure, deliberate drop.
    @Override
    public final void resetSecurity() {
        state = NO_SECURITY_LEVEL;
        wipeScpState();
        currentMasterKey = null;
    }

    // Internal session-only reset: used by SCP impls at INITIALIZE_UPDATE start to clear the previous
    // session's session keys without dropping the just-primed master. ssc deliberately persists across.
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
    public abstract short maxResponseLength();

    // SCP-specific cleanup: zero session keys + per-SCP crypto buffers (ICV, chaining, ...).
    protected abstract void wipeScpState();

    // KDD = last 2 bytes of the currently selected AID || CPLC bytes 10..17
    // (IC fab date || IC SN || IC batch ID). Mirrors how off-card tooling derives KDD
    // from the card's CPLC. Used by SCP02/SCP03 INITIALIZE_UPDATE.
    protected static byte[] sessionKDD() {
        var sim = Simulator.current();
        byte[] cplc = sim.getGlobalPlatform().cplc;
        byte[] aidBytes = AIDUtil.bytes(sim.getAID());
        byte[] aidTail = Arrays.copyOfRange(aidBytes, aidBytes.length - 2, aidBytes.length);
        return GPUtils.concatenate(aidTail, Arrays.copyOfRange(cplc, 10, 18));
    }
}
