// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.globalplatform.GPRegistryEntry;
import org.globalplatform.GPSystem;

public class RegistryEntry implements GPRegistryEntry {

    private final AID aid;
    byte state = GPSystem.APPLICATION_SELECTABLE;

    public RegistryEntry(AID aid) {
        this.aid = aid;
    }

    @Override
    public void deregisterService(short i) throws ISOException {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    @Override
    public AID getAID() {
        return aid;
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
