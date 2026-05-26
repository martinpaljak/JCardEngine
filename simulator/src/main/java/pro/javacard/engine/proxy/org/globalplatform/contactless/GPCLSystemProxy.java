// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.proxy.org.globalplatform.contactless;

import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.globalplatform.contactless.GPCLRegistryEntry;
import pro.javacard.engine.globalplatform.EngineRegistryEntry;

public final class GPCLSystemProxy {

    private GPCLSystemProxy() {
    }

    // Same lookup as GPSystem.getRegistryEntry, cast to GPCLRegistryEntry (EngineRegistryEntry
    // implements both). isDisabled() guard is defensive. getRegistryEntry never returns ELFs.
    public static GPCLRegistryEntry getGPCLRegistryEntry(AID aid) {
        EngineRegistryEntry entry = Simulator.current().gp().getRegistryEntry(aid);
        if (entry == null || entry.isDisabled()) {
            return null;
        }
        return entry;
    }

    public static GPCLRegistryEntry getNextGPCLRegistryEntry(GPCLRegistryEntry entry, short family) {
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        return null;
    }

    public static void setVolatilePriority(GPCLRegistryEntry entry) {
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }

    public static short getCardCLInfo(byte[] buffer, short offset, short info) {
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        return 0;
    }

    public static void setCommunicationInterface(short iface, boolean onOff) {
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }
}
