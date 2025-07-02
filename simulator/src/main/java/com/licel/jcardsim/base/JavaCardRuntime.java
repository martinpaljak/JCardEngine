package com.licel.jcardsim.base;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Shareable;

// The interface of the simulator towards JC implementation classes inside the engine itself
public interface JavaCardRuntime {

    AID getAID();

    AID lookupAID(byte buffer[], short offset, byte length);

    AID getPreviousContextAID();

    boolean isAppletSelecting(Object aThis);

    void sendAPDU(byte[] buffer, short bOff, short len);

    TransientMemory getTransientMemory();

    APDU getCurrentAPDU();

    byte getAssignedChannel();

    void beginTransaction();

    void abortTransaction();

    void commitTransaction();

    byte getTransactionDepth();

    short getUnusedCommitCapacity();

    short getMaxCommitCapacity();

    short getAvailablePersistentMemory();

    short getAvailableTransientResetMemory();

    short getAvailableTransientDeselectMemory();

    Shareable getSharedObject(AID serverAID, byte parameter);

    boolean isObjectDeletionSupported();

    void requestObjectDeletion();

    // Callback from Applet.register()
    void register(Object instance);

    // Callback from Applet.register()
    void register(Object instance, byte[] buffer, short offset, byte len);
}
