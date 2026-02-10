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
import pro.javacard.engine.JavaCardEngineException;
import pro.javacard.engine.core.ContextStackProxy;
import pro.javacard.engine.core.DependencyAnalyzer;
import pro.javacard.engine.core.Faulty;
import pro.javacard.engine.core.IsolatingClassReloader;
import pro.javacard.engine.faulty.FaultyConfig;
import pro.javacard.engine.globalplatform.GlobalPlatform;
import pro.javacard.engine.globalplatform.GlobalPlatformApplet;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.Semaphore;
import java.util.Optional;

/**
 * Simulates a JavaCard. This is the _external_ view of the simulated environment, and all external
 * manipulation MUST happen via these interfaces. Each Simulator is independent (like a single secure element)
 */
public class Simulator implements CardInterface, JavaCardEngine, JavaCardRuntime {
    static {
        System.setProperty("org.bouncycastle.rsa.no_lenstra_check", "true");
    }

    private static final Logger log = LoggerFactory.getLogger(Simulator.class);

    // default ATR - dummy minimal
    public static final String DEFAULT_ATR = "3B80800101";

    // If the simulator exposes object deletion support TODO: property
    public static final boolean OBJECT_DELETION_SUPPORTED = true;

    // Used to set the current simulator instance when two different simulators are run inside a single thread.
    private static final ThreadLocal<Simulator> currentSimulator = new ThreadLocal<>();

    // Isolates loaded applet classes to this simulator instance
    private final IsolatingClassReloader classLoader;

    // Used to keep track of the installation parameters during install()/register() callbacks
    private static final ThreadLocal<RegisterCallbackOptions> options = new ThreadLocal<>();

    // Guards session access.
    // NOTE: would like to use ReentrantLock but because we have to trigger a timeout from a scheduler
    // in SimulatorSession due to VSmartCard messaging discrepancies, a Semaphore is currently used instead.
    final Semaphore lock = new Semaphore(1, true);

    // The thread that creates this Simulator instance. Used for assisting warnings.
    final Thread creator = Thread.currentThread();

    // Installed applets. TODO: ApplicationInstance to GPRegistryEntry
    protected final SortedMap<AID, ApplicationInstance> applets = new TreeMap<>(AIDUtil.comparator());

    // Outbound transfer buffer
    protected final byte[] responseBuffer = new byte[Short.MAX_VALUE + 2];
    // Outbound transfer buffer length
    protected short responseBufferSize = 0;

    // Transient memory
    protected final TransientMemory transientMemory;
    // Global Platform support for registry and secure channel
    private final GlobalPlatform globalPlatform;
    // Handles APDU state and IO
    private final CurrentAPDU currentAPDU;

    // Currently selected applet
    private AID currentAID;

    // Context stack
    private final Deque<AID> contextStack = new ArrayDeque<>();

    // If applet selection is ongoing - FIXME: refactor
    private boolean selecting = false;

    // transaction depth
    private byte transactionDepth = 0;

    // Number of allocated bytes
    int bytesAllocated;

    // Set of package names for applets, to identify interesting code _before_ register is called.
    Set<String> interesting = new HashSet<>();

    // Fault injection configuration
    private FaultyConfig faultConfig;

    public Simulator(ClassLoader loader, FaultyConfig faultConfig, GlobalPlatform globalPlatform) {
        this.transientMemory = new TransientMemory();
        this.globalPlatform = globalPlatform;
        this.currentAPDU = new CurrentAPDU();
        this.classLoader = new IsolatingClassReloader(loader);
        this.faultConfig = faultConfig;
    }

    public Simulator(ClassLoader loader, FaultyConfig faultConfig) {
        this(loader, faultConfig, new GlobalPlatform());
    }

    public Simulator(ClassLoader loader) {
        this(loader, null);
    }

    public Simulator(FaultyConfig faultConfig) {
        this(Simulator.class.getClassLoader(), faultConfig);
    }

    public Simulator() throws RuntimeException {
        this(Simulator.class.getClassLoader(), null);
    }

    // When applet code calls back for the internal facade of the simulator,
    // return _this_ instance. This usually happens via JCSystem.*/GPSystem.* calls.
    // and is the mirror of current()

    @FunctionalInterface
    public interface CurrentSimulator extends AutoCloseable {
        // This interface exists solely to remove Exception from close() signature
        @Override
        void close();
    }

    // Use in try-with-resources block to have this simulator instance as current simulator
    public CurrentSimulator asCurrent() {
        currentSimulator.set(this);
        return currentSimulator::remove;
    }

    @Override
    public CurrentAPDU getCurrentAPDU() {
        return currentAPDU;
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
        var currentInstance = currentSimulator.get();
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
        return installApplet(aid, appletClass, parameters, false);
    }

    // These load the applet without class isolation, so that internals are exposed to caller.
    public AID installExposedApplet(AID aid, Class<? extends Applet> appletClass, byte[] params) {
        return installApplet(aid, appletClass, params, true);
    }

    public boolean selectApplet(AID aid) throws SystemException {
        var resp = selectAppletWithResult(aid);
        return ByteUtil.getSW(resp) == ISO7816.SW_NO_ERROR;
    }

    public byte[] selectAppletWithResult(AID aid) throws SystemException {
        return _transmitCommand(APDU.PROTOCOL_T0, AIDUtil.select(aid)); // FIXME: should either expose selectApplet on session or get rid of it.
    }

    public byte[] getATR() {
        // FIXME: remove from this layer unless GPSystem.setATRHistBytes gets implemented
        return Hex.decode(DEFAULT_ATR);
    }

    @SuppressWarnings("unused") // used from intercept
    public static byte[] allocateBytes(int size) {
        Simulator current = (Simulator) current();
        byte[] v = current.getTransientMemory().makeByteArray(size, JCSystem.MEMORY_TYPE_PERSISTENT);
        current.registerAllocation(v);
        return v;
    }

    @SuppressWarnings("unused") // used from intercept
    public static short[] allocateShorts(int size) {
        log.debug("Allocating short array");
        Simulator current = (Simulator) current();
        var v = current.getTransientMemory().makeShortArray((short) size, JCSystem.MEMORY_TYPE_PERSISTENT);
        current.registerAllocation(v);
        return v;
    }

    @SuppressWarnings("unused") // used from intercept
    public static boolean[] allocateBooleans(int size) {
        log.debug("Allocating boolean array");
        Simulator current = (Simulator) current();
        var v = current.getTransientMemory().makeBooleanArray((short) size, JCSystem.MEMORY_TYPE_PERSISTENT);
        current.registerAllocation(v);
        return v;
    }

    @SuppressWarnings("unused") // used from intercept
    public static void trackAllocation(Object array) {
        Simulator current = (Simulator) current();
        current.registerAllocation(array);
    }

    private void registerAllocation(Object array) {
        if (array == null) return;
        // Locate the caller
        StackWalker walker = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE);
        Optional<StackWalker.StackFrame> caller = walker.walk(frames -> frames
                .filter(f -> !f.getClassName().equals(Simulator.class.getName()))
                .findFirst());

        if (caller.isPresent()) {
             StackWalker.StackFrame frame = caller.get();
             String className = frame.getClassName();
             int line = frame.getLineNumber();
             
             // Normalize to dots
             className = className.replace('/', '.');

             log.trace("Allocation on {}:{} {}", className, line, Faulty.getSourceLine(className, line));
             // Delegate to TransientMemory
             transientMemory.registerAllocation(array, className, line);
        } else {
             log.warn("Caller not found for allocation");
        }
    }
    
    // Queries
    public Object getBuffer(String className, int line) {
        return transientMemory.getBuffer(className, line);
    }

    /**
     * @return current applet context AID or null
     */
    @Override
    public AID getAID() {
        return contextStack.peek();
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
        for (var aid : applets.keySet()) {
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
        for (var aid : applets.keySet()) {
            if (aid.equals(lookupAid)) {
                return applets.get(aid);
            }
        }
        log.warn("Application with AID {} not found", AIDUtil.toString(lookupAid));
        return null;
    }

    /**
     * Push an applet context AID onto the context stack. Used by GlobalPlatformApplet
     * to perform context switches for indirect personalization (GP 2.2.1 Section 7.3.3).
     */
    public void pushContext(AID aid) {
        contextStack.push(aid);
    }

    /**
     * Pop the top applet context AID from the context stack.
     */
    public void popContext() {
        contextStack.pop();
    }

    /**
     * @return previous selected applet context AID or null
     */
    @Override
    public AID getPreviousContextAID() {
        var it = contextStack.iterator();
        if (it.hasNext())
            it.next(); // skip current
        return it.hasNext() ? it.next() : null;
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
        var a = lookupApplet(aid);
        if (a == null) {
            return null;
        } else {
            return a.getApplet();
        }
    }

    public void internalDeleteApplet(AID aid) {
        log.info("Deleting applet {}", AIDUtil.toString(aid));
        var app = lookupApplet(aid);

        if (app == null) {
            throw new IllegalArgumentException("Applet with AID " + AIDUtil.toString(aid) + " not found");
        }

        var applet = app.getApplet();

        // See https://docs.oracle.com/en/java/javacard/3.1/guide/appletevent-uninstall-method.html
        // https://pinpasjc.win.tue.nl/docs/apis/jc222/javacard/framework/AppletEvent.html
        if (applet instanceof AppletEvent) {
            try {
                contextStack.clear();
                contextStack.push(aid);
                // Called by the Java Card runtime environment to inform this applet instance that the Applet Deletion Manager has been requested to delete it.
                // This method may be called by the Java Card runtime environment multiple times, once for each attempt to delete this applet instance.
                ((AppletEvent) applet).uninstall();
            } catch (Exception e) {
                contextStack.clear();
                // Exceptions thrown by this method are caught by the Java Card runtime environment and ignored.
                applets.remove(aid);
                // We delete it, but still throw, so that JavaCardEngine.deleteApplet() could be used for testing
                throw new JavaCardEngineException("uninstall() failed", e);
            }
        }
        applets.remove(aid);
        contextStack.clear();
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
        // We call into applet.
        try (var sim = asCurrent()) {
            // First deselect the applet, if it is currently selected.
            if (aid.equals(currentAID)) {
                deselect(lookupApplet(currentAID));
            }
            internalDeleteApplet(aid);
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
        // return aThis == getApplet(getAID()) && selecting;
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
        try (var session = connect()) {
            return session.transmitCommand(command);
        }
    }

    int command_counter = 0;

    byte[] _transmitCommand(byte protocol, byte[] command) throws SystemException {
        command_counter++;

        log.info("Processing command #{}", command_counter);
        // Reset faults
        correct();

        // Apply faults from config if set
        if (faultConfig != null) {
            var faults = faultConfig.getFaults(command_counter, command);
            for (var classEntry : faults.entrySet()) {
                var className = classEntry.getKey();
                for (var lineEntry : classEntry.getValue().entrySet()) {
                    int line = lineEntry.getKey();
                    var type = lineEntry.getValue();
                    applyFault(className, line, type);
                }
            }
        }

        try (var sim = asCurrent()) {
            log.trace("APDU: {}", Hex.toHexString(command));
            final var apduCase = APDUHelper.getAPDUCase(command);
            final var theSW = new byte[2];
            byte[] response;

            selecting = false;
            final Applet applet;
            final AID newAid;
            // check if there is an applet to be selected
            if (!APDUHelper.isExtendedAPDU(apduCase) && isAppletSelectionApdu(command)) {
                log.trace("Current AID {}, looking up applet ...",
                        currentAID == null ? null : AIDUtil.toString(currentAID));
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

            if (APDUHelper.isExtendedAPDU(apduCase)) {
                if (!(applet instanceof ExtendedLength)) {
                    Util.setShort(theSW, (short) 0, ISO7816.SW_WRONG_LENGTH);
                    return theSW;
                }
            }

            responseBufferSize = 0;
            var apdu = currentAPDU.getAPDU();
            try {
                if (selecting) {
                    // First call the select() method
                    log.trace("Calling Applet.select() of {}", AIDUtil.toString(newAid));
                    boolean success;
                    try {
                        contextStack.clear();
                        contextStack.push(newAid);
                        success = applet.select();
                    } catch (Exception e) {
                        log_exception(e, "Exception in Applet.select()");
                        success = false;
                    } finally {
                        contextStack.clear();
                    }
                    if (!success) {
                        log.warn("{} denied selection in Applet.select()", AIDUtil.toString(newAid));
                        // If the applet declines to be selected, the Java Card RE returns an APDU response status word of
                        // ISO7816.SW_APPLET_SELECT_FAILED to the CAD. Upon selection failure, the Java Card RE state
                        // is set to indicate that no applet is selected. See Section 4.6 Applet Selection for more details.
                        currentAID = null;
                        throw new ISOException(ISO7816.SW_APPLET_SELECT_FAILED);
                    } else {
                        currentAID = newAid;
                    }
                }
                currentAPDU.reset(protocol, command);
                contextStack.push(currentAID);
                applet.process(apdu);
                Util.setShort(theSW, (short) 0, (short) 0x9000);
            } catch (Throwable e) {
                Util.setShort(theSW, (short) 0, ISO7816.SW_UNKNOWN);
                if (e instanceof ISOException) {
                    Util.setShort(theSW, (short) 0, ((ISOException) e).getReason());
                } else {
                    log_exception(e, "Exception in process()");
                }
            } finally {
                selecting = false;
                currentAPDU.disable(); // APDU.getCurrentAPDU() will not be available
                contextStack.clear();
            }

            // if theSW = 0x61XX or 0x9XYZ than return data (ISO7816-3)
            if (theSW[0] == 0x61 || theSW[0] == 0x62 || theSW[0] == 0x63
                    || (theSW[0] >= (byte) 0x90 && theSW[0] <= (byte) 0x9F) || isNotAbortingCase(theSW)) {
                response = new byte[responseBufferSize + 2];
                Util.arrayCopyNonAtomic(responseBuffer, (short) 0, response, (short) 0, responseBufferSize);
                Util.arrayCopyNonAtomic(theSW, (short) 0, response, responseBufferSize, (short) 2);
            } else {
                response = theSW;
            }

            return response;
        }
    }

    static void log_exception(Throwable e, String message) {
        if (e.getClass().getName().startsWith("javacard.") || e.getClass().getName().startsWith("javacardx.")) {
            if (log.isTraceEnabled()) {
                log.warn("{}: {}", message, e.getClass().getName(), e);
            } else {
                log.warn("{}: {}", message, e.getClass().getName());
            }
        } else {
            log.warn("{}: {}", message, e.getClass().getSimpleName(), e);
        }
    }

    static boolean isAppletSelectionApdu(byte[] apdu) {
        final var channelMask = (byte) 0xFC; // mask out %b000000xx
        final var p2Mask = (byte) 0xE3; // mask out %b000xxx00

        final var cla = (byte) (apdu[ISO7816.OFFSET_CLA] & channelMask);
        final var ins = apdu[ISO7816.OFFSET_INS];
        final var p1 = apdu[ISO7816.OFFSET_P1];
        final var p2 = (byte) (apdu[ISO7816.OFFSET_P2] & p2Mask);

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

    protected AID findAppletForSelectApdu(byte[] selectApdu, int apduCase) {
        if (apduCase == APDUHelper.CASE1 || apduCase == APDUHelper.CASE2) {
            if (applets.containsKey(GlobalPlatformApplet.OPEN_AID)) {
                log.info("Selecting OPEN");
                return GlobalPlatformApplet.OPEN_AID;
            } else {
                return null;
            }
        }

        for (var aid : applets.keySet()) {
            if (aid.equals(selectApdu, ISO7816.OFFSET_CDATA, selectApdu[ISO7816.OFFSET_LC])) {
                log.trace("Selecting {} based on full AID match", AIDUtil.toString(aid));
                return aid;
            }
        }

        for (var aid : applets.keySet()) {
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
            var applet = app.getApplet();
            contextStack.push(app.getAID());
            applet.deselect();
        } catch (Exception e) {
            log_exception(e, "Exception in Applet.deselect()");
            // ignore all
        } finally {
            contextStack.pop();
        }

        currentAID = null;

        if (getTransactionDepth() != 0) {
            log.warn("Applet deselected with transactions pending");
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
        // FIXME: assumptions on APDU buffer size.
        responseBufferSize = Util.arrayCopyNonAtomic(buffer, bOff, responseBuffer, responseBufferSize, len);
    }

    /**
     * powerdown/powerup
     */
    @Override
    public void reset() {
        // FIXME: lock
        // lock.acquireUninterruptibly();
        Arrays.fill(responseBuffer, (byte) 0);
        transactionDepth = 0;
        responseBufferSize = 0;
        currentAID = null;
        contextStack.clear();
        command_counter = 0;
        transientMemory.clearOnReset();
        globalPlatform.reset();
        // lock.release();
    }

    @Override
    public TransientMemory getTransientMemory() {
        return transientMemory;
    }

    @Override
    public GlobalPlatform getGlobalPlatform() {
        return globalPlatform;
    }

    @Override
    public byte getAssignedChannel() {
        // TODO: MultiSelectable
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
     * @param serverAID the AID of the server applet
     * @param parameter optional parameter data
     * @return the shareable interface object or <code>null</code>
     * @see javacard.framework.JCSystem#getAppletShareableInterfaceObject(javacard.framework.AID, byte)
     */
    @Override
    public Shareable getSharedObject(AID serverAID, byte parameter) {
        log.info("Getting Shareable from {} in {}", AIDUtil.toString(serverAID), System.identityHashCode(this));
        var serverApplet = getApplet(serverAID);
        if (serverApplet == null) {
            log.warn("Did not find server AID {} in {}", AIDUtil.toString(serverAID), System.identityHashCode(this));
            return null;
        }
        var shareable = serverApplet.getShareableInterfaceObject(getAID(), parameter);
        if (shareable == null) {
            log.warn("{}({}) did not return a Shareable in {}", serverApplet.getClass().getSimpleName(),
                    AIDUtil.toString(serverAID), System.identityHashCode(this));
            return null;
        }
        // Wrap in context pusher
        return ContextStackProxy.wrap(serverAID, contextStack, shareable);
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

    @Override
    public void loadApplet(AID packageAid, AID appletAid, Class<? extends Applet> appletClass) {
        try (var sim = asCurrent()) {
            Simulator.current().getGlobalPlatform().loadClass(packageAid, appletAid, appletClass);
        }
    }

    @Override
    public AID internalInstallApplet(AID appletAID, Class<? extends Applet> appletClass, byte[] privileges,
            byte[] parameters, boolean exposed) {
        final Class<?> klass;

        log.info("Installing applet class {}, loaded by {}", appletClass.getName(),
                appletClass.getClassLoader().getName());

        var deps = DependencyAnalyzer.getAllPackages(appletClass);
        log.debug("Dependencies for {}: {}", appletClass.getSimpleName(), deps);

        if (exposed) {
            klass = appletClass;
        } else {
            try {
                klass = classLoader.reloadAndIsolate(appletClass);
            } catch (ClassNotFoundException e) {
                throw new IllegalArgumentException("Could not (re-)load " + appletClass.getName(), e);
            }
        }

        // Resolve the install() method
        Method installMethod;
        try {
            installMethod = klass.getMethod("install", byte[].class, short.class, byte.class);
        } catch (NoSuchMethodException e) {
            // NOTE: there is empty implementation in framework.Applet
            throw new IllegalArgumentException("Class does not provide install method");
        }

        // Check for magic field
        // TODO: same feature flag as for bytecode change
        try {
            var magic = klass.getField("jcardengine");
            magic.setBoolean(null, true);
        } catch (NoSuchFieldException e) {
            // Nothing.
        } catch (IllegalAccessException e) {
            log.warn("Could not set magic field: {}", e.getMessage());
        }

        // Construct _actual_ install parameters
        var install_parameters = Helpers.install_parameters(AIDUtil.bytes(appletAID), privileges, parameters);

        // Set the register() callback options
        options.set(new RegisterCallbackOptions(appletAID, exposed));

        interesting.add(klass.getPackageName());
        var from_gp = GlobalPlatformApplet.OPEN_AID.equals(contextStack.peek());
        // Call the install() method.
        try {
            contextStack.clear(); // It is from JCRE context
            installMethod.invoke(null, install_parameters, (short) 0, (byte) install_parameters.length);
        } catch (InvocationTargetException e) {
            log.warn("Exception in {} install() ", AIDUtil.toString(appletAID), e);
            if (e.getCause() instanceof ISOException) {
                var isoex = (ISOException) e.getCause();
                log.error(String.format("ISOException: 0x%04X", isoex.getReason()), isoex);
            }
            throw new JavaCardEngineException("Exception in install()", e);
        } catch (Exception e) {
            log.error("Error installing applet " + AIDUtil.toString(appletAID), e);
            throw new SystemException(SystemException.ILLEGAL_AID);
        } finally {
            // XXX: this is hacky
            if (from_gp) {
                contextStack.clear();
                contextStack.push(GlobalPlatformApplet.OPEN_AID);
            }
            interesting.clear();
        }
        if (options.get() != null) {
            log.warn("install() did not call register()");
            throw new JavaCardEngineException("install() did not call register()");
        }
        return appletAID;
    }

    private AID installApplet(AID appletAID, Class<? extends Applet> appletClass, byte[] parameters, boolean exposed) {
        try (var sim = asCurrent()) {
            // If there is a currently selected applet, deselect it. installApplet is like implicit selection of card manager
            if (currentAID != null) {
                deselect(lookupApplet(currentAID));
            }
            return internalInstallApplet(appletAID, appletClass, null, parameters, exposed);
        } finally {
            memstat();
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
            var instanceAID = options.get().aid;
            log.info("Registering {} as {} in {}", instance.getClass().getName(), AIDUtil.toString(instanceAID),
                    System.identityHashCode(this));

            applets.put(instanceAID, new ApplicationInstance(instanceAID, instance, options.get().exposed));
            // Now Applet.getAID() is available.
            contextStack.clear();
            contextStack.push(instanceAID);
        } finally {
            options.remove();
        }
    }

    // Callback from Applet.register()
    @Override
    public void register(Object instance, byte[] buffer, short offset, byte len) {
        try {
            var actual = new AID(buffer, offset, len);
            if (options.get() == null || applets.containsKey(actual))
                SystemException.throwIt(SystemException.ILLEGAL_AID);
            log.info("Registering {} as {} in {}", instance.getClass().getName(), AIDUtil.toString(actual),
                    System.identityHashCode(this));
            applets.put(actual, new ApplicationInstance(actual, instance, options.get().exposed));
            // Now Applet.getAID() is available.
            contextStack.clear();
            contextStack.push(actual);
        } finally {
            options.remove();
        }
    }

    public void correct() {
        for (var b : branch_flips.values()) {
            Arrays.fill(b, false);
        }
        for (var s : switch_flips.values()) {
            Arrays.fill(s, 0);
        }
    }

    private void applyFault(String className, int line, String type) {
        var branches = branch_flips.computeIfAbsent(className, k -> new boolean[MAX_LINE_NUMBER]);
        var switches = switch_flips.computeIfAbsent(className, k -> new int[MAX_LINE_NUMBER]);

        switch (type) {
            case "exception", "skip", "mutate" -> {
                branches[line] = true;
                switches[line] = Short.MAX_VALUE;
                var sourceLine = Faulty.getSourceLine(className, line);
                if (sourceLine != null) {
                    log.info("Applying {} fault at {}:{} → {}", type, className, line, sourceLine);
                } else {
                    log.info("Applying {} fault at {}:{}", type, className, line);
                }
            }
            default -> log.warn("Unknown fault type: {}", type);
        }
    }

    private static final int MAX_LINE_NUMBER = Short.MAX_VALUE;

    // Per-class boolean arrays for flipping conditionals
    private final HashMap<String, boolean[]> branch_flips = new HashMap<>();

    // Per-class int arrays for offsetting switch values
    private final HashMap<String, int[]> switch_flips = new HashMap<>();

    @SuppressWarnings("unused") // used from intercept
    public static boolean[] getFaultFlipsArray() {
        var current = (Simulator) Simulator.current();
        var className = getCallingClassName();
        var r = current.branch_flips.computeIfAbsent(className, k -> new boolean[MAX_LINE_NUMBER]);
        return r;
    }

    @SuppressWarnings("unused") // used from intercept
    public static int[] getFaultIntFlipsArray() {
        var current = (Simulator) Simulator.current();
        var className = getCallingClassName();
        var r = current.switch_flips.computeIfAbsent(className, k -> new int[MAX_LINE_NUMBER]);
        return r;
    }

    /**
     * Get the calling class name using StackWalker.
     */
    private static String getCallingClassName() {
        var walker = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE);
        return walker.walk(frames -> frames.skip(2) // Skip this method and the getFault*Array method
                .findFirst()
                .map(frame -> frame.getClassName())
                .orElse("unknown"));
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
        log.info("Connecting for {} with {}", timeout, protocol);
        return new SimulatorSession(this, protocol, timeout);
    }
}
