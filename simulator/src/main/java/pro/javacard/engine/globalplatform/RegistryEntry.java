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
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.globalplatform.GPRegistryEntry;
import org.globalplatform.GPSystem;

public class RegistryEntry implements GPRegistryEntry {

    byte state = GPSystem.APPLICATION_SELECTABLE;

    @Override
    public void deregisterService(short i) throws ISOException {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    @Override
    public AID getAID() {
        // TODO: currently only "this applet"
        return Simulator.current().getAID();
    }

    @Override
    public short getPrivileges(byte[] bytes, short i) throws ArrayIndexOutOfBoundsException {
        return 0;
    }

    @Override
    public byte getState() {
        return state;
    }

    @Override
    public boolean isAssociated(AID aid) {
        return false;
    }

    @Override
    public boolean isPrivileged(byte b) {
        return false;
    }

    @Override
    public void registerService(short i) throws ISOException {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    @Override
    public boolean setState(byte b) {
        // TODO: check requirements, store in registry
        state = b;
        return true;
    }
}
