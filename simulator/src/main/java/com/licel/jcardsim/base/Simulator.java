// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

import apdu4j.core.BIBO;
import pro.javacard.engine.core.DeterministicRandom;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.*;
import javacardx.apdu.ExtendedLength;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.engine.JavaCardEngineException;
import pro.javacard.engine.core.ContextStackProxy;
import pro.javacard.engine.core.DependencyAnalyzer;
import pro.javacard.engine.core.Faulty;
import pro.javacard.engine.core.IsolatingClassReloader;
import pro.javacard.engine.faulty.FaultyConfig;
import pro.javacard.engine.globalplatform.Context;
import pro.javacard.engine.globalplatform.EngineRegistryEntry;
import pro.javacard.engine.globalplatform.GlobalPlatformEngine;
import pro.javacard.engine.globalplatform.RegistryPolicy;
import pro.javacard.engine.globalplatform.SCPConfig;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.Semaphore;

/**
 * Simulates a JavaCard. This is the _external_ view of the simulated environment, and all external
 * manipulation MUST happen via these interfaces. Each Simulator is independent (like a single secure element)
 */
public class Simulator implements JavaCardEngine, JavaCardRuntime {
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

    // Outbound transfer buffer
    protected final byte[] responseBuffer = new byte[Short.MAX_VALUE + 2];
    // Outbound transfer buffer length
    protected short responseBufferSize = 0;

    // Transient memory
    protected final TransientMemory transientMemory;
    // Global Platform support for registry and secure channel
    private final GlobalPlatformEngine globalPlatform;
    // Handles APDU state and IO
    private final CurrentAPDU currentAPDU;

    // The applet currently selected on the channel (JCRE "active applet instance").
    // Not the same as the current executing context (contextStack.peek().getAID()).
    private AID activeAID;

    // Executing context stack. getAID/caller/getPreviousContextAID all derive from the top entry.
    private final Deque<EngineRegistryEntry> contextStack = new ArrayDeque<>();

    // If applet selection is ongoing - FIXME: refactor
    private boolean selecting = false;


    // transaction depth
    private byte transactionDepth = 0;

    // Number of allocated bytes
    int bytesAllocated;

    // Set of package names for applets, to identify interesting code _before_ register is called.
    Set<String> interesting = new HashSet<>();

    // Fault injection configuration
    private final FaultyConfig faultConfig;

    // GH #20: one SecureRandom per card. Real and non-blocking by default; deterministic when seeded.
    private final SecureRandom rng;

    public Simulator(ClassLoader loader, FaultyConfig faultConfig, GlobalPlatformEngine globalPlatform, Long seed) {
        this.transientMemory = new TransientMemory();
        this.globalPlatform = globalPlatform;
        this.currentAPDU = new CurrentAPDU(transientMemory);
        this.classLoader = new IsolatingClassReloader(loader);
        this.faultConfig = faultConfig;
        this.rng = seed == null ? new SecureRandom() : new DeterministicRandom(seed);
    }

    public Simulator(ClassLoader loader, FaultyConfig faultConfig, GlobalPlatformEngine globalPlatform) {
        this(loader, faultConfig, globalPlatform, null);
    }

    public Simulator(ClassLoader loader, FaultyConfig faultConfig) {
        this(loader, faultConfig, new GlobalPlatformEngine(SCPConfig.defaultConfig()));
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

    @Override
    public SecureRandom rng() {
        return rng;
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

    // Keeps track of selected applet and triggers deselect/select invocation
    private boolean _select(EngineRegistryEntry instance) {
        if (instance == null) {
            return false;
        }
        var aid = instance.getAID();
        if (activeAID != null) {
            deselect(globalPlatform.lookup(activeAID));
        }
        contextStack.clear();
        contextStack.push(instance);
        // JC API isAppletActive: the applet is the active instance during its own select() callback;
        // rolled back to null below if it refuses selection.
        activeAID = aid;
        boolean success;
        try {
            success = instance.getApplet().select();
        } catch (Throwable e) {
            log_exception(e, "Exception in Applet.select()");
            success = false;
        } finally {
            contextStack.clear();
        }
        // JCRE 3.2 4.6.2 step 7: select() true with a transaction in progress is a selection failure.
        if (success && getTransactionDepth() != 0) {
            log.warn("select() returned true with transaction in progress: {}", aid);
            abortTransaction();
            success = false;
        }
        if (!success) {
            activeAID = null;
        }
        return success;
    }

    public byte[] getATR() {
        // FIXME: remove from this layer unless GPSystem.setATRHistBytes gets implemented
        return Hex.decode(DEFAULT_ATR);
    }

    @SuppressWarnings("unused") // used from intercept
    public static byte[] allocateBytes(int size) {
        Simulator current = (Simulator) current();
        byte[] v = current.getTransientMemory().makeByteArray(size, JCSystem.MEMORY_TYPE_PERSISTENT, null);
        current.registerAllocation(v);
        return v;
    }

    @SuppressWarnings("unused") // used from intercept
    public static short[] allocateShorts(int size) {
        log.debug("Allocating short array");
        Simulator current = (Simulator) current();
        var v = current.getTransientMemory().makeShortArray((short) size, JCSystem.MEMORY_TYPE_PERSISTENT, null);
        current.registerAllocation(v);
        return v;
    }

    @SuppressWarnings("unused") // used from intercept
    public static boolean[] allocateBooleans(int size) {
        log.debug("Allocating boolean array");
        Simulator current = (Simulator) current();
        var v = current.getTransientMemory().makeBooleanArray((short) size, JCSystem.MEMORY_TYPE_PERSISTENT, null);
        current.registerAllocation(v);
        return v;
    }

    @SuppressWarnings("unused") // used from intercept
    public static void trackAllocation(Object array) {
        Simulator current = (Simulator) current();
        current.registerAllocation(array);
    }

    private void registerAllocation(Object array) {
        if (array == null) {
            return;
        }
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
        if (options.get() != null) {
            return null;
        }
        var top = contextStack.peek();
        return top == null ? null : top.getAID();
    }

    @Override
    public AID getActiveAID() {
        return activeAID;
    }

    @Override
    public EngineRegistryEntry caller() {
        return contextStack.peek();
    }

    @Override
    public Context activeContext() {
        var top = contextStack.peek();
        return top == null ? null : top.getContext();
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
        // The JCRE's sole registry read (JCSystem.lookupAID proxy): the "JC owned" AID instance for
        // selectable applet entries only. getApplets() already excludes ELFs (Kind.PKG).
        for (var e : globalPlatform.getApplets()) {
            if (e.getAID().equals(buffer, offset, length)) {
                return e.getAID();
            }
        }
        return null;
    }

    /**
     * @return previous selected applet context AID or null
     */
    @Override
    public AID getPreviousContextAID() {
        var it = contextStack.iterator();
        if (!it.hasNext()) {
            return null;
        }
        // JCRE 6.2.5: the AID active at the last context switch. Walk down past same-context frames
        // (e.g. same-package SIO) to the first frame with a different context. Null when the run was
        // entered directly from the JCRE context, which has no AID (6.2.5.1).
        var top = it.next().getContext();
        while (it.hasNext()) {
            var below = it.next();
            if (!Objects.equals(below.getContext(), top)) {
                return below.getAID();
            }
        }
        return null;
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
        var a = globalPlatform.lookup(aid);
        if (a == null) {
            return null;
        } else {
            return a.getApplet();
        }
    }

    public void internalDeleteApplet(AID aid) {
        log.info("Deleting applet {}", aid);
        var app = globalPlatform.lookup(aid);

        if (app == null) {
            throw new IllegalArgumentException("Applet with AID " + aid + " not found");
        }

        var applet = app.getApplet();
        JavaCardEngineException uninstallFailure = null;
        // Snapshot the caller's context so post-delete work (e.g. EVENT_DELETED fan-out) keeps it.
        var savedStack = new ArrayDeque<>(contextStack);

        if (applet instanceof AppletEvent) {
            try {
                contextStack.clear();
                contextStack.push(app);
                ((AppletEvent) applet).uninstall();
            } catch (Exception e) {
                // JCRE ignores uninstall() exceptions; we still throw so deleteApplet() is testable.
                uninstallFailure = new JavaCardEngineException("uninstall() failed", e);
            }
        }
        contextStack.clear();
        contextStack.addAll(savedStack);
        // The OPEN restores spec-defaulted privileges (still seeing the deletee's set) and removes it.
        globalPlatform.remove(aid);
        if (uninstallFailure != null) {
            throw uninstallFailure;
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
        // We call into applet.
        try (var sim = asCurrent()) {
            // First deselect the applet, if it is currently selected.
            if (aid.equals(activeAID)) {
                deselect(globalPlatform.lookup(activeAID));
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
    // Convenience: creates a session, sends one command, closes the session.
    public byte[] transceive(byte[] command) throws SystemException {
        if (creator != Thread.currentThread()) {
            log.error("Do not call from a different thread.");
        }
        try (var session = connect()) {
            return session.transceive(command);
        }
    }

    int command_counter = 0;

    byte[] _transceive(byte protocol, byte[] command) throws SystemException {
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
            // Set before the applet's select() runs, so getProtocol() reports the command's interface.
            currentAPDU.protocol = protocol;
            if (command_counter == 1) {
                // First command since reset (counter 0->1): power up on this interface and select the default applet.
                var implicit = RegistryPolicy.implicitlySelectedEntry(globalPlatform);
                if (!_select(implicit)) {
                    log.warn("Auto-select on power-up failed: {}", implicit);
                }
            }
            log.trace("APDU: {}", Hex.toHexString(command));
            final var apduCase = APDUHelper.getAPDUCase(command);
            final var theSW = new byte[2];
            byte[] response;

            // MANAGE CHANNEL (INS=0x70) - not supported
            if ((command[ISO7816.OFFSET_CLA] & 0x80) == 0x00 && command[ISO7816.OFFSET_INS] == 0x70) {
                log.warn("MANAGE CHANNEL not supported");
                Util.setShort(theSW, (short) 0, (short) 0x6881);
                return theSW;
            }

            selecting = false;
            final Applet applet;
            final EngineRegistryEntry newEntry;
            // check if there is an applet to be selected
            if (!APDUHelper.isExtendedAPDU(apduCase) && isAppletSelectionApdu(command)) {
                log.trace("Current AID {}, looking up applet ...", activeAID);
                // GPC v2.3.1 Table 11-81: P2 b2 set requests [next occurrence] - continue the search after activeAID.
                final var nextOccurrence = (command[ISO7816.OFFSET_P2] & 0x02) == 0x02;
                newEntry = RegistryPolicy.findAppletForSelectApdu(globalPlatform, command, apduCase, activeAID,
                        nextOccurrence);
                log.trace("Found {}", newEntry);
                if (newEntry == null) {
                    // SELECT [by name] miss (GPC v2.3.1 6.4.2.1.2): the current Application stays selected
                    // and the SELECT is dispatched to it; with nothing selected the OPEN returns 6A82.
                    if (activeAID == null) {
                        Util.setShort(theSW, (short) 0, ISO7816.SW_FILE_NOT_FOUND);
                        return theSW;
                    }
                    applet = globalPlatform.lookup(activeAID).getApplet();
                } else {
                    // applet was found, so we will trigger Applet.select() via _select() later
                    selecting = true;
                    applet = newEntry.getApplet();
                }
            } else {
                // Non-SELECT command with no applet active: JCRE 3.2 4.8 mandates 6999.
                if (activeAID == null) {
                    Util.setShort(theSW, (short) 0, ISO7816.SW_APPLET_SELECT_FAILED);
                    return theSW;
                }
                applet = globalPlatform.lookup(activeAID).getApplet();
                newEntry = null;
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
                    log.trace("Calling Applet.select(): {}", newEntry);
                    if (!_select(newEntry)) {
                        // JCRE 4.6: on refusal return SW_APPLET_SELECT_FAILED, nothing selected.
                        log.warn("Applet.select() denied selection: {}", newEntry);
                        throw new ISOException(ISO7816.SW_APPLET_SELECT_FAILED);
                    }
                }
                currentAPDU.reset(command);
                contextStack.push(globalPlatform.lookup(activeAID));
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
            if (theSW[0] == 0x61 || theSW[0] == 0x62 || theSW[0] == 0x63 || (theSW[0] >= (byte) 0x90 && theSW[0] <= (byte) 0x9F) || isNotAbortingCase(theSW)) {
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

        // GPC v2.3.1 Table 11-81: P2 b2 distinguishes [first or only occurrence] (0x00) from [next occurrence] (0x02)
        return cla == ISO7816.CLA_ISO7816 && ins == ISO7816.INS_SELECT && p1 == 0x04 && (p2 == 0x00 || p2 == 0x02);
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

    private void deselect(EngineRegistryEntry app) {
        log.trace("Applet.deselect(): {}", app.getAID());
        try {
            var applet = app.getApplet();
            contextStack.push(app);
            applet.deselect();
        } catch (Exception e) {
            log_exception(e, "Exception in Applet.deselect()");
            // ignore all
        } finally {
            contextStack.pop();
        }

        activeAID = null;

        if (getTransactionDepth() != 0) {
            log.warn("Applet deselected with transactions pending");
            abortTransaction();
        }
        // JCRE 5.1.2: clears only this context's CLEAR_ON_DESELECT arrays, and only when no other applet
        // in the same context remains selected.
        transientMemory.clearOnDeselect(app.getContext());
        // GPC v2.3.1 10.2.3: SC session closes when the Application Session ends, so the next
        // INITIALIZE_UPDATE re-resolves master keys via the new applet's associated-SD chain.
        globalPlatform.getSecureChannel().resetSecurity();
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

    // Power down: clear volatile state and arm power-up. Reachable only through a session that
    // closes with resetOnClose (SimulatorSession), never as a bare call.
    void reset() {
        // FIXME: lock
        // lock.acquireUninterruptibly();
        Arrays.fill(responseBuffer, (byte) 0);
        transactionDepth = 0;
        responseBufferSize = 0;
        activeAID = null;
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
    public GlobalPlatformEngine gp() {
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
     * @see javacard.framework.JCSystem#getAvailableMemory(byte)
     */
    @Override
    public int getAvailablePersistentMemory() {
        return transientMemory.getAvailablePersistentMemory();
    }

    /**
     * @param serverAID the AID of the server applet
     * @param parameter optional parameter data
     * @return the shareable interface object or <code>null</code>
     * @see javacard.framework.JCSystem#getAppletShareableInterfaceObject(javacard.framework.AID, byte)
     */
    @Override
    public Shareable getSharedObject(AID serverAID, byte parameter) {
        log.info("Getting Shareable from {} in {}", serverAID, System.identityHashCode(this));
        // JC API: null if the calling applet has not yet invoked Applet.register() - i.e. called from
        // install() before registration. options != null means we are mid-install before register().
        if (options.get() != null) {
            log.warn("getShareableInterfaceObject before caller register(): {}", serverAID);
            return null;
        }
        // JC API: null if serverAID is null (must not propagate as NPE from getApplet).
        if (serverAID == null) {
            return null;
        }
        var serverApplet = getApplet(serverAID);
        if (serverApplet == null) {
            log.warn("Did not find server AID {} in {}", serverAID, System.identityHashCode(this));
            return null;
        }
        // JC API: null if the server applet throws an uncaught exception.
        Shareable shareable;
        try {
            shareable = serverApplet.getShareableInterfaceObject(getAID(), parameter);
        } catch (Exception e) {
            log.warn("{}({}) threw during getShareableInterfaceObject: {}", serverApplet.getClass().getSimpleName(), serverAID, e.getMessage(), e);
            return null;
        }
        if (shareable == null) {
            log.warn("{}({}) did not return a Shareable in {}", serverApplet.getClass().getSimpleName(), serverAID, System.identityHashCode(this));
            return null;
        }
        // Wrap in context pusher
        return ContextStackProxy.wrap(globalPlatform.lookup(serverAID), contextStack, shareable);
    }

    // Platform-context SIO fetch: getShareableInterfaceObject(null, parameter), so the server
    // sees a null clientAID (system/CRS/OPEN caller). Used by CL event fan-out. GPC v2.3.1 Amd C 3.10.
    public Shareable getSystemSharedObject(AID serverAID, byte parameter) {
        var serverApplet = getApplet(serverAID);
        if (serverApplet == null) {
            return null;
        }
        var shareable = serverApplet.getShareableInterfaceObject(null, parameter);
        if (shareable == null) {
            return null;
        }
        // wrapPlatform suspends the applet stack so the callee sees getAID() == serverAID
        // and getPreviousContextAID() == null.
        return ContextStackProxy.wrapPlatform(globalPlatform.lookup(serverAID), contextStack, shareable);
    }

    // Context-switching proxy for a Shareable sub-interface, bypassing getShareableInterfaceObject().
    // Used for JCRE-internal cross-context dispatch (e.g. GP STORE DATA). Null if missing or no match.
    @Override
    public <S extends Shareable> S getInterface(AID aid, Class<S> iface) {
        var entry = globalPlatform.lookup(aid);
        if (entry == null) {
            return null;
        }
        var applet = entry.getApplet();
        if (!iface.isInstance(applet)) {
            return null;
        }
        return iface.cast(ContextStackProxy.wrap(entry, contextStack, (Shareable) applet));
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
            Simulator.current().gp().loadClass(packageAid, appletAid, appletClass, null);
        }
    }

    // pkg is the loaded PKG entry the install was certified against, or null for host install.
    @Override
    public AID internalInstallApplet(AID appletAID, Class<? extends Applet> appletClass, byte[] privileges,
                                     byte[] parameters, boolean exposed, EngineRegistryEntry pkg) {
        // Every applet must have a package; pkg == null is always a caller bug.
        if (pkg == null) {
            throw new IllegalStateException("internalInstallApplet requires a package");
        }
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
        // Real hardware passes install() the actual APDU buffer, not a separately allocated array.
        var install_buffer = currentAPDU.getBuffer();
        System.arraycopy(install_parameters, 0, install_buffer, 0, install_parameters.length);

        options.set(new RegisterCallbackOptions(appletAID, exposed, privileges, pkg));

        interesting.add(klass.getPackageName());
        var registered = false;
        // install() runs before register(), so the applet has no own entry yet.
        // Push the package entry so allocations are attributed to the right context.
        contextStack.push(pkg);
        try {
            installMethod.invoke(null, install_buffer, (short) 0, (byte) install_parameters.length);
            registered = options.get() == null;
        } catch (InvocationTargetException e) {
            log.warn("Exception in install(): {}", appletAID, e);
            if (e.getCause() instanceof ISOException isoex) {
                log.error(String.format("ISOException: 0x%04X", isoex.getReason()), isoex);
            }
            throw new JavaCardEngineException("Exception in install()", e);
        } catch (Exception e) {
            log.error("Error installing applet " + appletAID, e);
            throw new SystemException(SystemException.ILLEGAL_AID);
        } finally {
            contextStack.pop();
            interesting.clear();
            options.remove();
        }
        if (!registered) {
            log.warn("install() did not call register()");
            throw new JavaCardEngineException("install() did not call register()");
        }
        memstat();
        return appletAID;
    }

    private AID installApplet(AID appletAID, Class<? extends Applet> appletClass, byte[] parameters, boolean exposed) {
        try (var sim = asCurrent()) {
            // If there is a currently selected applet, deselect it. installApplet is like implicit selection of card manager
            if (activeAID != null) {
                deselect(globalPlatform.lookup(activeAID));
            }
            // Derive the package AID from the applet AID: strip the trailing instance byte,
            // or append a marker byte when the AID is already at the 5-byte minimum.
            // Both forms stay within the legal 5..16 byte range.
            var ab = AIDUtil.bytes(appletAID);
            var pkgAid = AIDUtil.create(ab.length > 5 ? Arrays.copyOf(ab, ab.length - 1) : Arrays.copyOf(ab, ab.length + 1));
            var pkg = globalPlatform.ensurePackage(pkgAid, appletAID, appletClass);
            // Install as the ISD, so install() sees getPreviousContextAID() == ISD like a GP install.
            contextStack.push(globalPlatform.isd());
            try {
                return internalInstallApplet(appletAID, appletClass, null, parameters, exposed, pkg);
            } finally {
                contextStack.pop();
            }
        }
    }

    // Callback from Applet.register()
    @Override
    public void register(Object instance) {
        try {
            var opts = options.get();
            registerAt(opts == null ? null : opts.aid(), instance, opts);
        } finally {
            options.remove();
        }
    }

    // Callback from Applet.register()
    @Override
    public void register(Object instance, byte[] buffer, short offset, byte len) {
        try {
            registerAt(new AID(buffer, offset, len), instance, options.get());
        } finally {
            options.remove();
        }
    }

    private void registerAt(AID instanceAID, Object instance, RegisterCallbackOptions opts) {
        if (opts == null || globalPlatform.lookup(instanceAID) != null) {
            log.warn("Already registered or not in install(): {}", instance.getClass().getName());
            SystemException.throwIt(SystemException.ILLEGAL_AID);
        }
        // GP pre-certifies the instance AID; reject divergence from the install-entry AID.
        if (!opts.aid().equals(instanceAID)) {
            log.warn("register() AID differs from install AID: {} vs {}", instanceAID, opts.aid());
            SystemException.throwIt(SystemException.ILLEGAL_AID);
        }
        log.info("Registering {} as {} in {}", instance.getClass().getName(), instanceAID, System.identityHashCode(this));
        globalPlatform.register(instanceAID, instance, opts.exposed(), opts.privileges(), opts.pkg());
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
                    log.info("Applying {} fault at {}:{} -> {}", type, className, line, sourceLine);
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
        var current = currentSimulator.get();
        var className = getCallingClassName();
        var r = current.branch_flips.computeIfAbsent(className, k -> new boolean[MAX_LINE_NUMBER]);
        return r;
    }

    @SuppressWarnings("unused") // used from intercept
    public static int[] getFaultIntFlipsArray() {
        var current = currentSimulator.get();
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

    // Per-thread context that register() consumes when an applet calls back during install().
    private record RegisterCallbackOptions(AID aid, boolean exposed, byte[] privileges, EngineRegistryEntry pkg) {
    }

    public void memstat() {
        log.info("Persistent         {}", transientMemory.getSumPersistent());
        log.info("CLEAR_ON_RESET:    {}", transientMemory.getSumCOR());
        log.info("CLEAR_ON_DESELECT: {}", transientMemory.getSumCOD());
    }

    @Override
    public BIBO connectFor(Duration timeout, String protocol, boolean resetOnClose) {
        log.info("Connecting for {} with {} reset={}", timeout, protocol, resetOnClose);
        return new SimulatorSession(this, protocol, timeout, resetOnClose);
    }
}
