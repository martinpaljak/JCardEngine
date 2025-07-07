/*
 * Copyright 2025 Martin Paljak
 * Copyright 2011 Licel LLC.
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

import com.licel.jcardsim.utils.AIDUtil;
import com.licel.jcardsim.utils.ByteUtil;
import javacard.framework.*;
import javacardx.apdu.ExtendedLength;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.engine.EngineSession;
import pro.javacard.engine.JavaCardEngine;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.Semaphore;

/**
 * Simulates a JavaCard. This is the _external_ view of the simulated environment, and all external
 * manipulation MUST happen via these interfaces. Each Simulator is independent (like a single secure element)
 */
public class Simulator implements CardInterface, JavaCardEngine, JavaCardRuntime {
    private static final Logger log = LoggerFactory.getLogger(Simulator.class);

    // default ATR - dummy minimal
    public static final String DEFAULT_ATR = "3B80800101";

    // If the simulator exposes object deletion support TODO: property
    public static final boolean OBJECT_DELETION_SUPPORTED = false;

    // Used to set the current simulator instance when two different simulators are run inside a single thread.
    private static final ThreadLocal<Simulator> currentSimulator = new ThreadLocal<>();

    // Isolates loaded applet classes to this simulator instance
    private IsolatingClassLoader classLoader = new IsolatingClassLoader(getClass().getClassLoader());

    // Used to keep track of the installation parameters during install()/register() callbacks
    private static final ThreadLocal<RegisterCallbackOptions> options = new ThreadLocal<>();

    // Guards session access.
    // NOTE: would like to use ReentrantLock but because we have to trigger a timeout from a scheduler
    // in SimulatorSession due to VSmartCard messaging discrepancies, a Semaphore is currently used instead.
    final Semaphore lock = new Semaphore(1, true);

    // The thread that creates this Simulator instance. Used for assisting warnings.
    final Thread creator = Thread.currentThread();

    // True if all applets all the time should be installed in exposed mode.
    private boolean exposed = false;

    // Installed applets
    protected final SortedMap<AID, ApplicationInstance> applets = new TreeMap<>(AIDUtil.comparator());

    // APDU class is final in JC API, this is a reset method.
    protected final Method apduPrivateResetMethod;
    // Outbound transfer buffer
    protected final byte[] responseBuffer = new byte[Short.MAX_VALUE + 2];
    // Outbound transfer buffer length
    protected short responseBufferSize = 0;

    // Transient memory
    protected final TransientMemory transientMemory;
    // APDU instance for short APDU-s
    protected final APDU shortAPDU;
    // APDU instance for extended APDU-s
    protected final APDU extendedAPDU;
    // Current applet context AID - FIXME: not correct
    protected AID currentAID;
    // Previously selected applet context - FIXME: not correct
    protected AID previousAID;
    // If applet selection is ongoing - FIXME: refactor
    protected boolean selecting = false;
    // If extended APDU-s are in use
    protected boolean usingExtendedAPDUs = false;
    // Current protocol
    protected byte currentProtocol = APDU.PROTOCOL_T0;
    // current protocol FIXME: doubled
    private String protocol = "T=0";

    // transaction depth
    protected byte transactionDepth = 0;

    // Number of allocated bytes
    int bytesAllocated;

    public Simulator() throws RuntimeException {
        this.transientMemory = new TransientMemory();
        // XXX: smell
        try {
            // The APDU implementation in JC API is final, so this is a hack to
            // have a custom constructor for different types of APDU-s in APDUProxy
            Constructor<?> ctor = APDU.class.getDeclaredConstructors()[0];
            ctor.setAccessible(true);

            shortAPDU = (APDU) ctor.newInstance(false);
            extendedAPDU = (APDU) ctor.newInstance(true);

            apduPrivateResetMethod = APDU.class.getDeclaredMethod("internalReset", byte.class, ApduCase.class, byte[].class);
            apduPrivateResetMethod.setAccessible(true);
        } catch (Exception e) {
            throw new RuntimeException("Internal reflection error", e);
        }
        // XXX: triggers reflective call into APDU instances.
        changeProtocol(protocol);
    }

    // When applet code calls back for the internal facade of the simulator,
    // return _this_ instance. This usually happens via JCSystem.* calls.
    // and is the mirror of current()
    // These are public so that tests that do not follow the convention can run with
    // minimal modification. TODO: make not public
    public void _makeCurrent() {
        currentSimulator.set(this);
    }

    public void _releaseCurrent() {
        currentSimulator.remove();
    }


    /**
     * Get the currently active Simulator instance
     * <p>
     * This method should be only called by internal implementation classes like
     * <code>JCSystem</code>
     *
     * @return current Simulator instance
     */
    public static JavaCardRuntime current() {
        Simulator currentInstance = currentSimulator.get();
        if (currentInstance == null) {
            throw new IllegalStateException("No current Engine instance");
        }
        return currentInstance;
    }

    @Override
    public AID installApplet(AID aid, Class<? extends Applet> appletClass, byte[] parameters) throws SystemException {
        if (creator != Thread.currentThread()) {
            log.error("Do not call from a different thread.");
        }
        return installApplet(aid, appletClass, parameters, exposed);
    }

    // These load the applet without class isolation, so that internals are exposed to caller.
    public AID installExposedApplet(AID aid, Class<? extends Applet> appletClass, byte[] params) {
        return installApplet(aid, appletClass, params, true);
    }

    public boolean selectApplet(AID aid) throws SystemException {
        byte[] resp = selectAppletWithResult(aid);
        return ByteUtil.getSW(resp) == ISO7816.SW_NO_ERROR;
    }

    public byte[] selectAppletWithResult(AID aid) throws SystemException {
        return _transmitCommand(AIDUtil.select(aid)); // XXX: should either expose selectApplet on session or get rid of it.
    }

    public byte[] getATR() {
        // FIXME: remove from this layer unless GPSystem.setATRHistBytes gets implemented
        return Hex.decode(DEFAULT_ATR);
    }

    // Convert the string based protocol into internal protocol byte used by JC
    private static byte getProtocolByte(String protocol) {
        Objects.requireNonNull(protocol, "protocol");
        String p = protocol.toUpperCase(Locale.ENGLISH).replace(" ", "");
        byte protocolByte;

        if (p.equals("T=0") || p.equals("*")) {
            protocolByte = APDU.PROTOCOL_T0;
        } else if (p.equals("T=1")) {
            protocolByte = APDU.PROTOCOL_T1;
        } else if (p.equals("T=CL,TYPE_A,T1") || p.equals("T=CL")) {
            protocolByte = APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A;
            protocolByte |= APDU.PROTOCOL_T1;
        } else if (p.equals("T=CL,TYPE_B,T1")) {
            protocolByte = APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B;
            protocolByte |= APDU.PROTOCOL_T1;
        } else {
            throw new IllegalArgumentException("Unknown protocol: " + protocol);
        }
        return protocolByte;
    }

    /**
     * Switch protocol
     * <p>
     * Supported protocols are:
     * <ul>
     *     <li><code>T=0</code> (alias: <code>*</code>)</li>
     *     <li><code>T=1</code></li>
     *     <li><code>T=CL, TYPE_A, T1</code></li>
     *     <li><code>T=CL, TYPE_B, T1</code></li>
     * </ul>
     *
     * @param protocol protocol to use
     * @throws java.lang.IllegalArgumentException for unknown protocols
     */
    void changeProtocol(String protocol) {
        changeProtocol(getProtocolByte(protocol));
        this.protocol = protocol;
    }

    /**
     * @return the current protocol string
     * @see #changeProtocol(String)
     */
    public String getProtocol() {
        return protocol;
    }


    /**
     * @return current applet context AID or null
     */
    @Override
    public AID getAID() {
        return currentAID;
    }

    /**
     * Lookup applet by aid contains in byte array
     *
     * @param buffer the byte array containing the AID bytes
     * @param offset the start of AID bytes in <code>buffer</code>
     * @param length the length of the AID bytes in <code>buffer</code>
     * @return Applet AID or null
     */
    @Override
    public AID lookupAID(byte[] buffer, short offset, byte length) {
        // To return the "JC owned" AID instance.
        for (AID aid : applets.keySet()) {
            if (aid.equals(buffer, offset, length)) {
                return aid;
            }
        }
        return null;
    }

    /**
     * Lookup applet by aid
     *
     * @param lookupAid applet AID
     * @return ApplicationInstance or null
     */
    public ApplicationInstance lookupApplet(AID lookupAid) {
        log.trace("Searching registry for {}", lookupAid == null ? null : AIDUtil.toString(lookupAid));
        // To return the "JC owned" AID instance.
        for (AID aid : applets.keySet()) {
            if (aid.equals(lookupAid)) {
                return applets.get(aid);
            }
        }
        log.warn("Application with AID {} not found", AIDUtil.toString(lookupAid));
        return null;
    }

    /**
     * FIXME: this is bogus
     *
     * @return previous selected applet context AID or null
     */
    @Override
    public AID getPreviousContextAID() {
        return previousAID;
    }

    /**
     * Return <code>Applet</code> by it's AID or null
     *
     * @param aid applet <code>AID</code>
     * @return Applet or null
     */
    @Override
    public Applet getApplet(AID aid) {
        Objects.requireNonNull(aid);
        ApplicationInstance a = lookupApplet(aid);
        if (a == null) {
            return null;
        } else {
            return a.getApplet();
        }
    }

    /**
     * Delete applet
     *
     * @param aid Applet AID to delete
     */
    @Override
    public void deleteApplet(AID aid) {
        if (creator != Thread.currentThread()) {
            log.error("Do not call from a different thread.");
        }
        _makeCurrent(); // We call into applet.
        try {
            if (currentAID != null) {
                deselect(lookupApplet(currentAID));
            }
            log.info("Deleting applet {}", AIDUtil.toString(aid));
            ApplicationInstance app = lookupApplet(aid);

            if (app == null) {
                throw new IllegalArgumentException("Applet with AID " + AIDUtil.toString(aid) + " not found");
            }

            Applet applet = app.getApplet();

            // See https://docs.oracle.com/en/java/javacard/3.1/guide/appletevent-uninstall-method.html
            // https://pinpasjc.win.tue.nl/docs/apis/jc222/javacard/framework/AppletEvent.html
            if (applet instanceof AppletEvent) {
                try {
                    // Called by the Java Card runtime environment to inform this applet instance that the Applet Deletion Manager has been requested to delete it.
                    // This method may be called by the Java Card runtime environment multiple times, once for each attempt to delete this applet instance.
                    ((AppletEvent) applet).uninstall();
                } catch (Exception e) {
                    // Exceptions thrown by this method are caught by the Java Card runtime environment and ignored.
                    log.warn("Applet.uninstall() failed", e);
                }
            }

            applets.remove(aid);
            currentAID = null;
        } finally {
            _releaseCurrent();
        }
    }

    /**
     * Check if applet is currently being selected
     *
     * @param aThis applet
     * @return true if applet is being selected
     */
    @Override
    public boolean isAppletSelecting(Object aThis) {
        return selecting;
        // NOTE: there is a proxy in play, so identity makes no sense.
        //return aThis == getApplet(getAID()) && selecting;
    }

    /**
     * Transmit APDU to previously selected applet or select a new applet
     *
     * @param command command apdu
     * @return response apdu
     */
    @Override
    public byte[] transmitCommand(byte[] command) throws SystemException {
        if (creator != Thread.currentThread()) {
            log.error("Do not call from a different thread.");
        }
        try (EngineSession session = connect()) {
            return session.transmitCommand(command);
        }
    }

    byte[] _transmitCommand(byte[] command) throws SystemException {
        _makeCurrent();
        try {
            log.trace("APDU: {}", Hex.toHexString(command));
            final ApduCase apduCase = ApduCase.getCase(command);
            final byte[] theSW = new byte[2];
            byte[] response;

            selecting = false;
            final Applet applet;
            final AID newAid;
            // check if there is an applet to be selected
            if (!apduCase.isExtended() && isAppletSelectionApdu(command)) {
                log.trace("Current AID {}, looking up applet ...", currentAID == null ? null : AIDUtil.toString(currentAID));
                newAid = findAppletForSelectApdu(command, apduCase);
                log.trace("Found {}", newAid == null ? null : AIDUtil.toString(newAid));
                // Nothing currently selected
                if (currentAID == null) {
                    // No applet found
                    if (newAid == null) {
                        Util.setShort(theSW, (short) 0, ISO7816.SW_FILE_NOT_FOUND);
                        return theSW;
                    } else {
                        selecting = true;
                        applet = lookupApplet(newAid).getApplet();
                    }
                } else {
                    // Application currently selected
                    if (newAid == null) {
                        // new application not found, send the SELECT APDU to current applet
                        applet = lookupApplet(currentAID).getApplet();
                    } else {
                        // run deselect
                        deselect(lookupApplet(currentAID));
                        // This APDU is selecting
                        selecting = true;
                        applet = lookupApplet(newAid).getApplet();
                    }
                }
            } else {
                // Nothing selected and not a SELECT applet - done
                if (currentAID == null) {
                    Util.setShort(theSW, (short) 0, ISO7816.SW_COMMAND_NOT_ALLOWED);
                    return theSW;
                }
                applet = lookupApplet(currentAID).getApplet();
                newAid = null;
            }

            if (apduCase.isExtended()) {
                if (applet instanceof ExtendedLength) {
                    usingExtendedAPDUs = true;
                } else {
                    Util.setShort(theSW, (short) 0, ISO7816.SW_WRONG_LENGTH);
                    return theSW;
                }
            } else {
                usingExtendedAPDUs = false;
            }

            responseBufferSize = 0;
            APDU apdu = getCurrentAPDU();
            try {
                if (selecting) {
                    currentAID = newAid; // so that JCSystem.getAID() would return the right thing
                    log.trace("Calling Applet.select() of {}", AIDUtil.toString(currentAID));
                    boolean success;
                    try {
                        success = applet.select();
                    } catch (Exception e) {
                        log.error("Exception in Applet.select(): {}", e.getMessage(), e);
                        success = false;
                    }
                    if (!success) {
                        log.warn("{} denied selection in Applet.select()", AIDUtil.toString(currentAID));
                        // If the applet declines to be selected, the Java Card RE returns an APDU response status word of
                        // ISO7816.SW_APPLET_SELECT_FAILED to the CAD. Upon selection failure, the Java Card RE state
                        // is set to indicate that no applet is selected. See Section 4.6 Applet Selection for more details.
                        currentAID = null;
                        throw new ISOException(ISO7816.SW_APPLET_SELECT_FAILED);
                    }
                }

                // set apdu
                resetAPDU(apdu, apduCase, command);

                applet.process(apdu);
                Util.setShort(theSW, (short) 0, (short) 0x9000);
            } catch (Throwable e) {
                Util.setShort(theSW, (short) 0, ISO7816.SW_UNKNOWN);
                if (e instanceof ISOException) {
                    Util.setShort(theSW, (short) 0, ((ISOException) e).getReason());
                } else {
                    if (e.getClass().getName().startsWith("javacard.") || e.getClass().getName().startsWith("javacardx.")) {
                        log.error("Exception in process(): {}", e.getClass().getName());
                    } else {
                        log.error("Exception in process(): {}", e.getClass().getSimpleName(), e);
                    }
                    log.trace("Trace", e);
                }
            } finally {
                selecting = false;
                resetAPDU(apdu, null, null);
            }

            // if theSW = 0x61XX or 0x9XYZ than return data (ISO7816-3)
            if (theSW[0] == 0x61 || theSW[0] == 0x62 || theSW[0] == 0x63 || (theSW[0] >= (byte) 0x90 && theSW[0] <= (byte) 0x9F) || isNotAbortingCase(theSW)) {
                response = new byte[responseBufferSize + 2];
                Util.arrayCopyNonAtomic(responseBuffer, (short) 0, response, (short) 0, responseBufferSize);
                Util.arrayCopyNonAtomic(theSW, (short) 0, response, responseBufferSize, (short) 2);
            } else {
                response = theSW;
            }

            return response;
        } finally {
            _releaseCurrent();
        }
    }

    static boolean isAppletSelectionApdu(byte[] apdu) {
        final byte channelMask = (byte) 0xFC; // mask out %b000000xx
        final byte p2Mask = (byte) 0xE3; // mask out %b000xxx00

        final byte cla = (byte) (apdu[ISO7816.OFFSET_CLA] & channelMask);
        final byte ins = apdu[ISO7816.OFFSET_INS];
        final byte p1 = apdu[ISO7816.OFFSET_P1];
        final byte p2 = (byte) (apdu[ISO7816.OFFSET_P2] & p2Mask);

        return cla == ISO7816.CLA_ISO7816 && ins == ISO7816.INS_SELECT && p1 == 0x04 && p2 == 0x00;
    }

    /**
     * Check if secure channel is not aborted
     * This method must be override in subclass that have secure channel abort checking
     *
     * @param SW Status word
     * @return True if secure channel is not aborted
     */
    protected boolean isNotAbortingCase(byte[] SW) {
        return false;
    }

    protected AID findAppletForSelectApdu(byte[] selectApdu, ApduCase apduCase) {
        if (apduCase == ApduCase.Case1 || apduCase == ApduCase.Case2) {
            // on a regular Smartcard we would select the CardManager applet
            // in this case we just select the first applet
            // XXX: does not belong here
            currentAID = null;
            return null;
        }

        for (AID aid : applets.keySet()) {
            if (aid.equals(selectApdu, ISO7816.OFFSET_CDATA, selectApdu[ISO7816.OFFSET_LC])) {
                log.trace("Selecting {} based on full AID match", AIDUtil.toString(aid));
                return aid;
            }
        }

        for (AID aid : applets.keySet()) {
            if (aid.partialEquals(selectApdu, ISO7816.OFFSET_CDATA, selectApdu[ISO7816.OFFSET_LC])) {
                log.trace("Selecting {} based on partial AID match", AIDUtil.toString(aid));
                return aid;
            }
        }

        return null;
    }

    private void deselect(ApplicationInstance app) {
        log.trace("Applet.deselect(): {}", AIDUtil.toString(app.getAID()));
        try {
            Applet applet = app.getApplet();
            applet.deselect();
        } catch (Exception e) {
            log.warn("Applet.deselect() failed", e);
            // ignore all
        }

        currentAID = null;

        if (getTransactionDepth() != 0) {
            abortTransaction();
        }
        transientMemory.clearOnDeselect();
    }

    /**
     * Copy response bytes to internal buffer
     *
     * @param buffer source byte array
     * @param bOff   the starting offset in buffer
     * @param len    the length in bytes of the response
     */
    @Override
    public void sendAPDU(byte[] buffer, short bOff, short len) {
        responseBufferSize = Util.arrayCopyNonAtomic(buffer, bOff, responseBuffer, responseBufferSize, len);
    }

    /**
     * powerdown/powerup
     */
    @Override
    public void reset() {
        // FIXME: lock
        //lock.acquireUninterruptibly();
        Arrays.fill(responseBuffer, (byte) 0);
        transactionDepth = 0;
        responseBufferSize = 0;
        currentAID = null;
        previousAID = null;
        transientMemory.clearOnReset();
        //lock.release();
    }

    @Override
    public TransientMemory getTransientMemory() {
        return transientMemory;
    }

    protected void resetAPDU(APDU apdu, ApduCase apduCase, byte[] buffer) {
        try {
            apduPrivateResetMethod.invoke(apdu, currentProtocol, apduCase, buffer);
        } catch (Exception e) {
            throw new RuntimeException("Internal reflection error", e);
        }
    }

    @Override
    public APDU getCurrentAPDU() {
        return usingExtendedAPDUs ? extendedAPDU : shortAPDU;
    }

    /**
     * Change protocol
     *
     * @param protocol protocol bits
     * @see javacard.framework.APDU#getProtocol()
     */
    private void changeProtocol(byte protocol) {
        this.currentProtocol = protocol;
        resetAPDU(shortAPDU, null, null);
        resetAPDU(extendedAPDU, null, null);
    }

    @Override
    public byte getAssignedChannel() {
        return 0; // basic channel
    }

    /**
     * @see javacard.framework.JCSystem#beginTransaction()
     */
    @Override
    public void beginTransaction() {
        if (transactionDepth != 0) {
            TransactionException.throwIt(TransactionException.IN_PROGRESS);
        }
        transactionDepth = 1;
    }

    /**
     * @see javacard.framework.JCSystem#abortTransaction()
     */
    @Override
    public void abortTransaction() {
        if (transactionDepth == 0) {
            TransactionException.throwIt(TransactionException.NOT_IN_PROGRESS);
        }
        transactionDepth = 0;
    }

    /**
     * @see javacard.framework.JCSystem#commitTransaction()
     */
    @Override
    public void commitTransaction() {
        if (transactionDepth == 0) {
            TransactionException.throwIt(TransactionException.NOT_IN_PROGRESS);
        }
        transactionDepth = 0;
    }

    /**
     * @return 1 if transaction in progress, 0 if not
     * @see javacard.framework.JCSystem#getTransactionDepth()
     */
    @Override
    public byte getTransactionDepth() {
        return transactionDepth;
    }

    /**
     * @return The current implementation always returns 32767
     * @see javacard.framework.JCSystem#getUnusedCommitCapacity()
     */
    @Override
    public short getUnusedCommitCapacity() {
        return Short.MAX_VALUE;
    }

    /**
     * @return The current implementation always returns 32767
     * @see javacard.framework.JCSystem#getMaxCommitCapacity()
     */
    @Override
    public short getMaxCommitCapacity() {
        return Short.MAX_VALUE;
    }

    /**
     * @return The current implementation always returns 32767
     * @see javacard.framework.JCSystem#getAvailableMemory(byte)
     */
    @Override
    public short getAvailablePersistentMemory() {
        return Short.MAX_VALUE;
    }

    /**
     * @return The current implementation always returns 32767
     * @see javacard.framework.JCSystem#getAvailableMemory(byte)
     */
    @Override
    public short getAvailableTransientResetMemory() {
        return Short.MAX_VALUE;
    }

    /**
     * @return The current implementation always returns 32767
     * @see javacard.framework.JCSystem#getAvailableMemory(byte)
     */
    @Override
    public short getAvailableTransientDeselectMemory() {
        return Short.MAX_VALUE;
    }

    /**
     * @param serverAID the AID of the server applet
     * @param parameter optional parameter data
     * @return the shareable interface object or <code>null</code>
     * @see javacard.framework.JCSystem#getAppletShareableInterfaceObject(javacard.framework.AID, byte)
     */
    @Override
    public Shareable getSharedObject(AID serverAID, byte parameter) {
        log.info("Getting Shareable from {} in {}", AIDUtil.toString(serverAID), System.identityHashCode(this));
        Applet serverApplet = getApplet(serverAID);
        if (serverApplet != null) {
            return serverApplet.getShareableInterfaceObject(getAID(), parameter);
        }
        log.warn("Did not find server AID {} in {}", AIDUtil.toString(serverAID), System.identityHashCode(this));
        return null;
    }

    /**
     * @return always false
     * @see javacard.framework.JCSystem#isObjectDeletionSupported()
     */
    @Override
    public boolean isObjectDeletionSupported() {
        return OBJECT_DELETION_SUPPORTED;
    }

    /**
     * @see javacard.framework.JCSystem#requestObjectDeletion()
     */
    @Override
    public void requestObjectDeletion() {
        if (!isObjectDeletionSupported()) {
            throw new SystemException(SystemException.ILLEGAL_USE);
        }
    }

    private AID installApplet(AID appletAID, Class<? extends Applet> appletClass, byte[] parameters, boolean exposed) {
        _makeCurrent();
        try {
            // If there is a currently selected applet, deselect it. installApplet is like implicit selection of card manager
            if (currentAID != null) {
                deselect(lookupApplet(currentAID));
            }

            final Class<?> klass;

            if (exposed) {
                klass = appletClass;
            } else {
                // Add explicit isolation for loaded class.
                classLoader.isolate(appletClass.getPackageName());
                try {
                    klass = classLoader.loadClass(appletClass.getName());
                } catch (ClassNotFoundException e) {
                    throw new IllegalArgumentException("Could not (re-)load " + appletClass.getName());
                }
            }

            // Resolve the install() method
            Method installMethod;
            try {
                installMethod = klass.getMethod("install", byte[].class, short.class, byte.class);
            } catch (NoSuchMethodException e) {
                throw new IllegalArgumentException("Class does not provide install method");
            }

            // Check for magic field
            // TODO: same feature flag as for bytecode change
            try {
                Field magic = klass.getField("jcardengine");
                magic.setBoolean(null, true);
            } catch (NoSuchFieldException e) {
                // Nothing.
            } catch (IllegalAccessException e) {
                log.warn("Could not set magic field: {}", e.getMessage());
            }

            // Construct _actual_ install parameters
            byte[] install_parameters = Helpers.install_parameters(AIDUtil.bytes(appletAID), parameters);

            // Set the register() callback options
            options.set(new RegisterCallbackOptions(appletAID, exposed));

            // Call the install() method.
            try {
                installMethod.invoke(null, install_parameters, (short) 0, (byte) install_parameters.length);
            } catch (InvocationTargetException e) {
                log.error("Exception in {} install() ", AIDUtil.toString(appletAID), e);
                if (e.getCause() instanceof ISOException) {
                    ISOException isoex = (ISOException) e.getCause();
                    log.error(String.format("ISOException: 0x%04X", isoex.getReason()), isoex);
                }
                throw new SystemException(SystemException.ILLEGAL_AID);
            } catch (Exception e) {
                log.error("Error installing applet " + AIDUtil.toString(appletAID), e);
                throw new SystemException(SystemException.ILLEGAL_AID);
            } finally {
                if (options.get() != null) {
                    log.error("install() did not call register()");
                    SystemException.throwIt(SystemException.ILLEGAL_AID);
                }
            }
            return appletAID;
        } finally {
            memstat();
            _releaseCurrent();
        }
    }

    // Callback from Applet.register()
    @Override
    public void register(Object instance) {
        try {
            // Already registered or not via install() or already registered.
            if (options.get() == null || applets.containsKey(options.get().aid)) {
                log.warn("{} already registered or not called from install()", instance.getClass().getName());
                SystemException.throwIt(SystemException.ILLEGAL_AID);
            }
            AID instanceAID = options.get().aid;
            log.info("Registering {} as {} in {}", instance.getClass().getName(), AIDUtil.toString(instanceAID), System.identityHashCode(this));

            applets.put(instanceAID, new ApplicationInstance(instanceAID, instance, options.get().exposed));
        } finally {
            options.remove();
        }
    }

    // Callback from Applet.register()
    @Override
    public void register(Object instance, byte[] buffer, short offset, byte len) {
        try {
            AID actual = new AID(buffer, offset, len);
            if (options.get() == null || applets.containsKey(actual))
                SystemException.throwIt(SystemException.ILLEGAL_AID);
            log.info("Registering {} as {} in {}", instance.getClass().getName(), AIDUtil.toString(actual), System.identityHashCode(this));
            applets.put(actual, new ApplicationInstance(actual, instance, options.get().exposed));
        } finally {
            options.remove();
        }
    }

    // Intercepted from bytecode
    public static byte[] allocate(int size) {
        Simulator current = (Simulator) Simulator.current(); // XXX: shortcut
        current.bytesAllocated += size;
        log.trace("Allocating {} bytes in {}; total is {}", size, System.identityHashCode(current), current.bytesAllocated);
        return new byte[size];
    }

    // Indicate packages to include in isolated classloader
    public Simulator isolate(String... packageNames) {
        classLoader.isolate(packageNames);
        return this;
    }


    private static class RegisterCallbackOptions {
        public final AID aid;
        public final boolean exposed;

        public RegisterCallbackOptions(AID aid, boolean exposed) {
            this.aid = aid;
            this.exposed = exposed;
        }
    }

    public void memstat() {
        log.info("Persistent         {}", bytesAllocated);
        log.info("CLEAR_ON_RESET:    {}", transientMemory.getSumCOR());
        log.info("CLEAR_ON_DESELECT: {}", transientMemory.getSumCOD());
    }

    @Override
    public EngineSession connectFor(Duration timeout, String protocol) {
        return new SimulatorSession(this, protocol, timeout);
    }

    @Override
    public JavaCardEngine exposed(boolean flag) {
        this.exposed = flag;
        return this;
    }

    @Override
    public JavaCardEngine withClassLoader(ClassLoader loader) {
        this.classLoader = new IsolatingClassLoader(loader);
        return this;
    }
}
