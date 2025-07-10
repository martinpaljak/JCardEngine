/*
 * Copyright 2025 Martin Paljak <martin@martinpaljak.net>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package pro.javacard.engine.globalplatform;

import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import org.globalplatform.*;

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
            // TODO: return "this applet"
            return new RegistryEntry();
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
