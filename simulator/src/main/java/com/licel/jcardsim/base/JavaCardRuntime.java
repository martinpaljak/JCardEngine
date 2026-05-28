// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.Shareable;
import pro.javacard.engine.globalplatform.EngineRegistryEntry;
import pro.javacard.engine.globalplatform.GlobalPlatformEngine;

// The interface of the simulator towards JC implementation classes inside the engine itself
public interface JavaCardRuntime {

    AID internalInstallApplet(AID appletAID, Class<? extends Applet> appletClass, byte[] privileges, byte[] parameters, boolean exposed, EngineRegistryEntry pkg);

    void internalDeleteApplet(AID aid);

    AID getAID();

    // The active applet instance (JC RE): the applet currently selected on the channel, or null.
    // Distinct from getAID() (the current executing context).
    AID getActiveAID();

    // Currently executing applet's registry entry, or null in platform context.
    EngineRegistryEntry caller();

    AID lookupAID(byte[] buffer, short offset, byte length);

    AID getPreviousContextAID();

    boolean isAppletSelecting(Object aThis);

    void sendAPDU(byte[] buffer, short bOff, short len);

    TransientMemory getTransientMemory();

    CurrentAPDU getCurrentAPDU();

    byte getAssignedChannel();

    void beginTransaction();

    void abortTransaction();

    void commitTransaction();

    byte getTransactionDepth();

    short getUnusedCommitCapacity();

    short getMaxCommitCapacity();

    int getAvailablePersistentMemory();

    Shareable getSharedObject(AID serverAID, byte parameter);

    // Platform-context SIO fetch (null clientAID = system/CRS/OPEN). GPC v2.3.1 Amd C 3.10.
    Shareable getSystemSharedObject(AID serverAID, byte parameter);

    // Context-switching proxy for a Shareable sub-interface, bypassing getShareableInterfaceObject().
    <S extends Shareable> S getInterface(AID aid, Class<S> iface);

    boolean isObjectDeletionSupported();

    void requestObjectDeletion();

    // Callback from Applet.register()
    void register(Object instance);

    // Callback from Applet.register()
    void register(Object instance, byte[] buffer, short offset, byte len);

    // Registry and secure channel
    GlobalPlatformEngine gp();
}
