// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.proxy.org.globalplatform;

import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import org.globalplatform.*;

public class GPSystemProxy {

    public static byte getCardContentState() {
        var entry = getRegistryEntry(null);
        return entry == null ? 0 : entry.getState();
    }

    public static byte getCardState() {
        return Simulator.current().gp().getCardState();
    }

    // GP API 1.8 GPSystem.getCVM and getSecureChannel: the OPEN resolves both through the calling
    // Application's own registry entry, which an applet that has not called register() does not have.
    public static CVM getCVM(byte bCVMIdentifier) {
        if (bCVMIdentifier == GPSystem.CVM_GLOBAL_PIN && Simulator.current().currentApplication() != null) {
            return Simulator.current().gp().getGlobalPIN();
        }
        return null;
    }

    public static SecureChannel getSecureChannel() {
        if (Simulator.current().currentApplication() == null) {
            return null;
        }
        return Simulator.current().gp().getSecureChannel();
    }

    public static GPRegistryEntry getRegistryEntry(AID reqAID) {
        return Simulator.current().gp().getRegistryEntry(reqAID);
    }

    // GPC v2.3.1 8.1.2 resolves the Global Services Application; GP API 1.8 GPSystem.getService then
    // fetches its SIO with getShareableInterfaceObject(clientAID, GLOBAL_SERVICE_IDENTIFIER).
    public static GlobalService getService(AID serverAID, short sServiceName) {
        var entry = Simulator.current().gp().resolveService(serverAID, sServiceName);
        if (entry == null) {
            return null;
        }
        var sio = Simulator.current().getSharedObject(entry, GPSystem.GLOBAL_SERVICE_IDENTIFIER);
        return sio instanceof GlobalService service ? service : null;
    }

    public static boolean lockCard() {
        return Simulator.current().gp().lockCard();
    }

    public static boolean setATRHistBytes(byte[] baBuffer, short sOffset, byte bLength) {
        return false;
    }

    public static boolean setCardContentState(byte bState) {
        return Simulator.current().gp().setCardContentState(bState);
    }

    public static boolean terminateCard() {
        return Simulator.current().gp().terminateCard();
    }
}
