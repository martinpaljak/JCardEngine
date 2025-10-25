/*
 * Copyright 2025 Martin Paljak
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
package com.licel.jcardsim.base;

import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.Shareable;
import pro.javacard.engine.globalplatform.GlobalPlatform;

// The interface of the simulator towards JC implementation classes inside the engine itself
public interface JavaCardRuntime {

    AID internalInstallApplet(AID appletAID, Class<? extends Applet> appletClass, byte[] parameters, boolean exposed);

    void internalDeleteApplet(AID aid);

    AID getAID();

    AID lookupAID(byte buffer[], short offset, byte length);

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

    short getAvailablePersistentMemory();

    Shareable getSharedObject(AID serverAID, byte parameter);

    boolean isObjectDeletionSupported();

    void requestObjectDeletion();

    // Callback from Applet.register()
    void register(Object instance);

    // Callback from Applet.register()
    void register(Object instance, byte[] buffer, short offset, byte len);

    // Registry and secure channel
    GlobalPlatform getGlobalPlatform();

}
