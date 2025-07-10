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

import org.globalplatform.CVM;
import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

public class GlobalPlatform {
    private final SCP03SecureChannelImpl sc = new SCP03SecureChannelImpl();
    private final GlobalPINImpl gpin = new GlobalPINImpl();

    private byte card_state = GPSystem.CARD_SECURED;

    public SecureChannel getSecureChannel() {
        return sc;
    }

    public void reset() {
        sc.resetSecurity();
    }

    public CVM getGlobalPIN() {
        return gpin;
    }

    public byte getCardState() {
        return card_state;
    }

    public boolean lockCard() {
        // The OPEN shall check that the Application invoking this method has the Card Lock Privilege. If not, the transition shall be rejected.
        card_state = GPSystem.CARD_LOCKED;
        return false;
    }

    public boolean terminateCard() {
        // The OPEN shall check that the Application invoking this method has the Card Terminate Privilege. If not, the transition shall be rejected.
        card_state = GPSystem.CARD_TERMINATED;
        return false;
    }
}
