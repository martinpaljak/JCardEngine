// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.Shareable;
import pro.javacard.engine.globalplatform.Context;
import pro.javacard.engine.globalplatform.EngineRegistryEntry;
import pro.javacard.engine.globalplatform.GlobalPlatformEngine;

import java.security.SecureRandom;

// The interface of the simulator towards JC implementation classes inside the engine itself
public interface JavaCardRuntime {

    EngineRegistryEntry internalInstallApplet(AID appletAID, Class<? extends Applet> appletClass, byte[] privileges, byte[] parameters, boolean exposed, EngineRegistryEntry pkg);

    void internalDeleteApplet(AID aid);

    AID getAID();

    // The active applet instance (JC RE): the applet currently selected on the channel, or the one
    // being installed. Distinct from getAID() (the current executing context).
    AID getActiveAID();

    // The Application executing now, in GP API terms "the Application invoking this method". Null when
    // there is none: the JCRE context, or an applet inside install() that has not called register() and
    // so is in no registry to be found in.
    EngineRegistryEntry currentApplication();

    // Active firewall context (JCRE 3.2 6.1.2); Context.JCRE when no applet frame is executing.
    Context activeContext();

    // Whether the given context is the currently selected applet's (JCRE 3.2 6.1.5).
    boolean isSelectedContext(Context context);

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

    // The per-card random source (GH #20: one SecureRandom per card)
    SecureRandom rng();
}
