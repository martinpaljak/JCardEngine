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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;

/**
 * Simulates a JavaCard. This is the _external_ view of the simulated environment, and all external
 * manipulation MUST happen via these interfaces. Each Simulator is independent (like a single secure element)
 */
public class Simulator implements CardInterface, JavaCardSimulator {
    private static final Logger log = LoggerFactory.getLogger(Simulator.class);

    // default ATR - NXP JCOP 31/36K
    public static final String DEFAULT_ATR = "3BFA1800008131FE454A434F5033315632333298";
    // ATR system property name
    public static final String ATR_SYSTEM_PROPERTY = "com.licel.jcardsim.card.ATR";
    // If the simulator exposes object deletion support TODO: property
    public static final boolean OBJECT_DELETION_SUPPORTED = false;

    // Used to set the current simulator instance when two different simulators are run inside a single thread.
    private static final ThreadLocal<Simulator> currentSimulator = new ThreadLocal<>();

    private final IsolatingClassLoader classLoader = new IsolatingClassLoader(getClass().getClassLoader());

    private static ThreadLocal<InstallOperationOptions> options = new ThreadLocal<>();

    // Installed applets
    protected final SortedMap<AID, ApplicationInstance> applets = new TreeMap<>(AIDUtil.comparator());

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

    public Simulator() {
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
    public static Simulator current() {
        Simulator currentInstance = currentSimulator.get();
        if (currentInstance == null) {
            throw new AssertionError("No current Simulator instance");
        }
        return currentInstance;
    }

    @Override
    public AID installApplet(AID aid, Class<? extends Applet> appletClass, byte[] parameters) throws SystemException {
        return installApplet(aid, appletClass, parameters, false);
    }

    // Wrappers around the main install method
    public AID installApplet(AID aid, Class<? extends Applet> appletClass, byte bArray[], short bOffset, byte bLength) throws SystemException {
        return installApplet(aid, appletClass, Arrays.copyOfRange(bArray, bOffset, bOffset + bLength));
    }

    public AID installApplet(AID aid, Class<? extends Applet> appletClass) {
        return installApplet(aid, appletClass, new byte[0], false);
    }

    // These load the applet without class isolation, so that internals are exposed to caller.
    public AID installExposedApplet(AID aid, Class<? extends Applet> appletClass, byte[] params) {
        return installApplet(aid, appletClass, params, true);
    }

    public AID installExposedApplet(AID aid, Class<? extends Applet> appletClass) {
        return installApplet(aid, appletClass, new byte[0], true);
    }

    public boolean selectApplet(AID aid) throws SystemException {
        byte[] resp = selectAppletWithResult(aid);
        return ByteUtil.getSW(resp) == ISO7816.SW_NO_ERROR;
    }

    public byte[] selectAppletWithResult(AID aid) throws SystemException {
        return transmitCommand(AIDUtil.select(aid));
    }

    public byte[] getATR() {
        // FIXME: remove from this layer unless GPSystem.setATRHistBytes gets implemented
        return Hex.decode(System.getProperty(ATR_SYSTEM_PROPERTY, DEFAULT_ATR));
    }

    protected static byte getProtocolByte(String protocol) {
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
    // XXX: changing protocol during session is not really a thing.
    public void changeProtocol(String protocol) {
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
    public AID lookupAID(byte buffer[], short offset, byte length) {
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
        log.info("Searching registry for {}", lookupAid == null ? null : AIDUtil.toString(lookupAid));
        // To return the "JC owned" AID instance.
        for (AID aid : applets.keySet()) {
            if (aid.equals(lookupAid)) {
                return applets.get(aid);
            }
        }
        log.error("application with AID {} not found", AIDUtil.toString(lookupAid));
        return null;
    }

    /**
     * @return previous selected applet context AID or null
     */
    public AID getPreviousContextAID() {
        return previousAID;
    }

    /**
     * Return <code>Applet</code> by it's AID or null
     *
     * @param aid applet <code>AID</code>
     * @return Applet or null
     */
    protected Applet getApplet(AID aid) {
        // FIXME: this should NOT be called with null.
        //Objects.requireNonNull(aid);
        if (aid == null) {
            return null;
        }
        ApplicationInstance a = lookupApplet(aid);
        if (a == null) return null;
        else return a.getApplet();
    }

    /**
     * Delete applet
     *
     * @param aid Applet AID to delete
     */
    @Override
    public void deleteApplet(AID aid) {
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
    public boolean isAppletSelecting(Object aThis) {
        return selecting;
        // NOTE: there is a proxy in play, so identity makes no sense.
        //return aThis == getApplet(getAID()) && selecting;
    }

    /**
     * Transmit APDU to previous selected applet
     *
     * @param command command apdu
     * @return response apdu
     */
    @Override
    public byte[] transmitCommand(byte[] command) throws SystemException {
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
                log.info("Current AID {}, looking up applet ...", currentAID == null ? null : AIDUtil.toString(currentAID));
                newAid = findAppletForSelectApdu(command, apduCase);
                log.info("Found {}", newAid == null ? null : AIDUtil.toString(newAid));
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
                    log.info("Calling Applet.select() of {}", AIDUtil.toString(currentAID));
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
        log.info("Applet.deselect(): {}", AIDUtil.toString(app.getAID()));
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
    public void sendAPDU(byte[] buffer, short bOff, short len) {
        responseBufferSize = Util.arrayCopyNonAtomic(buffer, bOff, responseBuffer, responseBufferSize, len);
    }

    /**
     * powerdown/powerup
     */
    public void reset() {
        Arrays.fill(responseBuffer, (byte) 0);
        transactionDepth = 0;
        responseBufferSize = 0;
        currentAID = null;
        previousAID = null;
        transientMemory.clearOnReset();
    }

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

    public APDU getCurrentAPDU() {
        return usingExtendedAPDUs ? extendedAPDU : shortAPDU;
    }

    /**
     * Change protocol
     *
     * @param protocol protocol bits
     * @see javacard.framework.APDU#getProtocol()
     */
    public void changeProtocol(byte protocol) {
        this.currentProtocol = protocol;
        resetAPDU(shortAPDU, null, null);
        resetAPDU(extendedAPDU, null, null);
    }

    public byte getAssignedChannel() {
        return 0; // basic channel
    }

    /**
     * @see javacard.framework.JCSystem#beginTransaction()
     */
    public void beginTransaction() {
        if (transactionDepth != 0) {
            TransactionException.throwIt(TransactionException.IN_PROGRESS);
        }
        transactionDepth = 1;
    }

    /**
     * @see javacard.framework.JCSystem#abortTransaction()
     */
    public void abortTransaction() {
        if (transactionDepth == 0) {
            TransactionException.throwIt(TransactionException.NOT_IN_PROGRESS);
        }
        transactionDepth = 0;
    }

    /**
     * @see javacard.framework.JCSystem#commitTransaction()
     */
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
    public byte getTransactionDepth() {
        return transactionDepth;
    }

    /**
     * @return The current implementation always returns 32767
     * @see javacard.framework.JCSystem#getUnusedCommitCapacity()
     */
    public short getUnusedCommitCapacity() {
        return Short.MAX_VALUE;
    }

    /**
     * @return The current implementation always returns 32767
     * @see javacard.framework.JCSystem#getMaxCommitCapacity()
     */
    public short getMaxCommitCapacity() {
        return Short.MAX_VALUE;
    }

    /**
     * @return The current implementation always returns 32767
     * @see javacard.framework.JCSystem#getAvailableMemory(byte)
     */
    public short getAvailablePersistentMemory() {
        return Short.MAX_VALUE;
    }

    /**
     * @return The current implementation always returns 32767
     * @see javacard.framework.JCSystem#getAvailableMemory(byte)
     */
    public short getAvailableTransientResetMemory() {
        return Short.MAX_VALUE;
    }

    /**
     * @return The current implementation always returns 32767
     * @see javacard.framework.JCSystem#getAvailableMemory(byte)
     */
    public short getAvailableTransientDeselectMemory() {
        return Short.MAX_VALUE;
    }

    /**
     * @param serverAID the AID of the server applet
     * @param parameter optional parameter data
     * @return the shareable interface object or <code>null</code>
     * @see javacard.framework.JCSystem#getAppletShareableInterfaceObject(javacard.framework.AID, byte)
     */
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
    public boolean isObjectDeletionSupported() {
        return OBJECT_DELETION_SUPPORTED;
    }

    /**
     * @see javacard.framework.JCSystem#requestObjectDeletion()
     */
    public void requestObjectDeletion() {
        if (!isObjectDeletionSupported()) {
            throw new SystemException(SystemException.ILLEGAL_USE);
        }
    }

    protected static boolean isAppletSelectionApdu(byte[] apdu) {
        final byte channelMask = (byte) 0xFC; // mask out %b000000xx
        final byte p2Mask = (byte) 0xE3; // mask out %b000xxx00

        final byte cla = (byte) (apdu[ISO7816.OFFSET_CLA] & channelMask);
        final byte ins = apdu[ISO7816.OFFSET_INS];
        final byte p1 = apdu[ISO7816.OFFSET_P1];
        final byte p2 = (byte) (apdu[ISO7816.OFFSET_P2] & p2Mask);

        return cla == ISO7816.CLA_ISO7816 && ins == ISO7816.INS_SELECT && p1 == 0x04 && p2 == 0x00;
    }

    private AID installApplet(AID appletAID, Class<? extends Applet> appletClass, byte[] parameters, boolean exposed) {
        _makeCurrent();

        try {
            // If there is a currently selected applet, deselect it. installApplet is like implicit selection of card manager
            if (currentAID != null) {
                deselect(lookupApplet(currentAID));
            }

            final Class<?> isolated;

            try {
                isolated = exposed ? appletClass : classLoader.loadClass(appletClass.getName());
            } catch (ClassNotFoundException e) {
                throw new IllegalArgumentException("Could not (re-)load " + appletClass.getName());
            }

            // Resolve the install method
            Method installMethod;
            try {
                installMethod = isolated.getMethod("install", byte[].class, short.class, byte.class);
            } catch (NoSuchMethodException e) {
                throw new IllegalArgumentException("Class does not provide install method");
            }

            // Construct _actual_ install parameters
            byte[] install_parameters = Helpers.install_parameters(AIDUtil.bytes(appletAID), parameters);

            // Call the install() method.
            options.set(new InstallOperationOptions(appletAID, exposed));
            try {
                installMethod.invoke(null, install_parameters, (short) 0, (byte) install_parameters.length);
            } catch (InvocationTargetException e) {
                log.error("Error installing applet " + AIDUtil.toString(appletAID), e);
                try {
                    ISOException isoException = (ISOException) e.getCause();
                    throw isoException;
                } catch (ClassCastException cce) { // FIXME: smell
                    throw new SystemException(SystemException.ILLEGAL_AID);
                }
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
            _releaseCurrent();
        }
    }

    // Callback from Applet.register()
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
        Simulator current = Simulator.current();
        log.trace("Allocating {} bytes in {}", size, System.identityHashCode(current));
        current.bytesAllocated += size;
        return new byte[size];
    }


    private static class InstallOperationOptions {
        public final AID aid;
        public final boolean exposed;

        public InstallOperationOptions(AID aid, boolean exposed) {
            this.aid = aid;
            this.exposed = exposed;
        }
    }
}
