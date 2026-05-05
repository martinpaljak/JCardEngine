// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.Shareable;
import pro.javacard.engine.globalplatform.EngineRegistryEntry;
import pro.javacard.engine.globalplatform.GlobalPlatform;

import java.util.Collection;

// The interface of the simulator towards JC implementation classes inside the engine itself
public interface JavaCardRuntime {

    AID internalInstallApplet(AID appletAID, Class<? extends Applet> appletClass, byte[] privileges, byte[] parameters, boolean exposed, AID packageAID);

    void internalDeleteApplet(AID aid);

    EngineRegistryEntry lookupApplet(AID aid);

    Collection<EngineRegistryEntry> getApplets();

    AID getAID();

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

    // Get a context-switching proxy for a Shareable sub-interface implemented by an applet.
    // Bypasses Applet.getShareableInterfaceObject() — used for JCRE-internal cross-context dispatch
    // (e.g. GP STORE DATA into a Personalization/Application target).
    <S extends Shareable> S getInterface(AID aid, Class<S> iface);

    boolean isObjectDeletionSupported();

    void requestObjectDeletion();

    // Callback from Applet.register()
    void register(Object instance);

    // Callback from Applet.register()
    void register(Object instance, byte[] buffer, short offset, byte len);

    // Registry and secure channel
    GlobalPlatform getGlobalPlatform();
}
