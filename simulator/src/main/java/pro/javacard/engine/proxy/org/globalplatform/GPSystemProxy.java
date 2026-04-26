// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.proxy.org.globalplatform;

import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import org.globalplatform.*;
import pro.javacard.engine.globalplatform.RegistryEntry;

public class GPSystemProxy {

    public static byte getCardContentState() {
        return getRegistryEntry(null).getState();
    }

    public static byte getCardState() {
        return Simulator.current().getGlobalPlatform().getCardState();
    }

    public static CVM getCVM(byte bCVMIdentifier) {
        if (bCVMIdentifier == GPSystem.CVM_GLOBAL_PIN) {
            return Simulator.current().getGlobalPlatform().getGlobalPIN();
        }
        return null;
    }

    public static SecureChannel getSecureChannel() {
        return Simulator.current().getGlobalPlatform().getSecureChannel();
    }

    public static GPRegistryEntry getRegistryEntry(AID reqAID) {
        if (reqAID == null) {
            return new RegistryEntry(Simulator.current().getAID());
        }
        return null;
    }

    public static GlobalService getService(AID serverAID, short sServiceName) {
        return null;
    }

    public static boolean lockCard() {
        return Simulator.current().getGlobalPlatform().lockCard();
    }

    public static boolean setATRHistBytes(byte[] baBuffer, short sOffset, byte bLength) {
        return false;
    }

    public static boolean setCardContentState(byte bState) {
        return false;
    }

    public static boolean terminateCard() {
        return Simulator.current().getGlobalPlatform().terminateCard();
    }
}
