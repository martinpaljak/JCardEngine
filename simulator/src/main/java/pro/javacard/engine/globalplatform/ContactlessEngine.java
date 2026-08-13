// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import com.licel.jcardsim.base.JavaCardRuntime;
import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.globalplatform.contactless.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.gp.GPRegistryEntry.Privilege;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

// The CRS side of the OPEN: contactless event dispatch and CL state policy.
public final class ContactlessEngine {
    private static final Logger log = LoggerFactory.getLogger(ContactlessEngine.class);

    // Symbolic CLAppletEvent names (EVENT_ prefix stripped) for log readability, mapped once via reflection.
    private static final Map<Short, String> EVENT_NAMES = buildEventNames();

    private ContactlessEngine() {
    }

    private static Map<Short, String> buildEventNames() {
        var names = new HashMap<Short, String>();
        try {
            for (Field f : CLAppletEvent.class.getDeclaredFields()) {
                if (f.getType() == short.class) {
                    names.put(f.getShort(null), f.getName().replace("EVENT_", ""));
                }
            }
        } catch (Exception e) {
            log.warn("Could not map CLAppletEvent names: {}", e.getMessage());
        }
        return names;
    }

    private static String eventName(short event) {
        return EVENT_NAMES.getOrDefault(event, "0x" + Integer.toHexString(event & 0xFFFF));
    }

    // Fan out a CL event for cl, originator = the calling Application: CREL fan-out (3.10.2), CRS implicit
    // subscription (3.10.3), self-delivery (3.10.4). Originator and EVENT_DELETED-self are suppressed.
    // A throwing callee is logged and skipped; remaining recipients still fire.
    public static void notifyContactlessEvent(EngineRegistryEntry cl, short event) {
        var sim = Simulator.current();
        // Originator = on-card actor that triggered the chain (caller of the API, or the SD/CRS in its
        // process method). Null at boot = no originator, suppress nothing.
        var callerEntry = sim.currentApplication();
        AID originator = callerEntry == null ? null : callerEntry.getAID();
        AID crsAID = RegistryPolicy.findHolder(sim.gp(), Privilege.ContactlessActivation).map(EngineRegistryEntry::getAID).orElse(null);
        var delivered = new HashSet<AID>();

        // GPC v2.3.1 Amd C 3.10.2 CREL fan-out.
        for (var aid : cl.internalGetCRELs()) {
            if (aid.equals(originator)) {
                continue;
            }
            if (deliverToCREL(sim, aid, cl, event)) {
                delivered.add(aid);
            }
        }

        // GPC v2.3.1 Amd C 3.10.3 CRS implicit subscription
        if (crsAID != null && !crsAID.equals(originator) && !delivered.contains(crsAID)) {
            deliverToCREL(sim, crsAID, cl, event);
        }

        // GPC v2.3.1 Amd C 3.10.4 self-delivery; never on own EVENT_DELETED, never when self is the originator.
        if (event == CLAppletEvent.EVENT_DELETED) {
            return;
        }
        var ownAID = cl.getAID();
        if (ownAID.equals(originator)) {
            return;
        }
        var sio = sim.getSystemSharedObject(ownAID, GPCLSystem.GPCL_CL_APPLICATION);
        if (sio instanceof CLApplet self) {
            try {
                log.info("{}: {} -> {}", eventName(event), ownAID, ownAID);
                self.notifyCLEvent(event);
            } catch (Exception e) {
                log.warn("CLApplet {} notifyCLEvent failed on event 0x{}", ownAID, Integer.toHexString(event & 0xFFFF), e);
            }
        } else if (sio != null) {
            log.warn("{} returned instead of CLApplet", sio.getClass().getSimpleName());
        }
    }

    // Dispatch to a CREL SIO. Returns true iff the SIO was found and the call did not throw
    private static boolean deliverToCREL(JavaCardRuntime sim, AID aid, EngineRegistryEntry cl, short event) {
        var sio = sim.getSystemSharedObject(aid, GPCLSystem.GPCL_CREL_APPLICATION);
        if (sio instanceof CRELApplication crel) {
            try {
                log.info("{}: {} -> {}", eventName(event), cl.getAID(), aid);
                crel.notifyCLEvent(cl, event);
            } catch (Exception e) {
                log.warn("CREL {} notifyCLEvent failed on event 0x{}", aid, Integer.toHexString(event & 0xFFFF), e);
            }
            return true;
        } else if (sio != null) {
            log.warn("{} returned instead of CRELApplication", sio.getClass().getSimpleName());
        }
        return false;
    }

    // Notify one CREL of a list-mutation event (EVENT_CREL_ADDED/REMOVED). Delegates to the shared
    // CREL delivery path so logging and error handling live in one place.
    public static void notifyCRELListChange(EngineRegistryEntry cl, AID affected, short event) {
        deliverToCREL(Simulator.current(), affected, cl, event);
    }

    // Caller-authorized CL state change (GPC v2.3.1 Amd C 3.11.4.2.2 + 7.1/7.2). Auth:
    // DEACTIVATED self|CONTACTLESS_ACTIVATION|CREL | ACTIVATED self=SELF_ACTIVATION or CONTACTLESS_ACTIVATION,
    // cross=CONTACTLESS_ACTIVATION | NON_ACTIVATABLE self only.
    public static byte setCLState(EngineRegistryEntry cl, byte state) {
        var caller = Simulator.current().currentApplication();
        if (caller == null) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            return 0;
        }
        boolean self = caller.getAID().equals(cl.getAID());
        // GPC v2.3.1 Amd C 8.1: a LOCKED or NON_ACTIVATABLE Application cannot be activated,
        // regardless of caller privilege. Refused outright, never delegated to the CRS.
        if (state == GPCLRegistryEntry.STATE_CL_ACTIVATED
                && (cl.isLocked() || cl.internalGetCLState() == GPCLRegistryEntry.STATE_CL_NON_ACTIVATABLE)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        boolean allowed = switch (state) {
            // GPC v2.3.1 Amd C 8.1 / 3.8.2: self, the CONTACTLESS_ACTIVATION holder, or a CREL on cl's
            // list may deactivate; any other caller is a cross-applet contactless DoS.
            case GPCLRegistryEntry.STATE_CL_DEACTIVATED -> self
                    || caller.isPrivileged(GPCLRegistryEntry.PRIVILEGE_CONTACTLESS_ACTIVATION)
                    || cl.internalGetCRELs().contains(caller.getAID());
            case GPCLRegistryEntry.STATE_CL_NON_ACTIVATABLE -> self;
            case GPCLRegistryEntry.STATE_CL_ACTIVATED -> self
                    ? caller.isPrivileged(GPCLRegistryEntry.PRIVILEGE_CONTACTLESS_SELF_ACTIVATION)
                            || caller.isPrivileged(GPCLRegistryEntry.PRIVILEGE_CONTACTLESS_ACTIVATION)
                    : caller.isPrivileged(GPCLRegistryEntry.PRIVILEGE_CONTACTLESS_ACTIVATION);
            default -> false;
        };
        if (!allowed) {
            // Unprivileged self-activation routes to the CRS for adjudication; other denials stay 6982.
            if (self && state == GPCLRegistryEntry.STATE_CL_ACTIVATED && delegateToCRS(cl)) {
                return cl.getCLState();
            }
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        // GPC v2.3.1 Amd C 8.2: before activating another Application that is currently DEACTIVATED,
        // the OPEN asks its CLAppletActivationPolicy whether it accepts.
        if (state == GPCLRegistryEntry.STATE_CL_ACTIVATED && !self
                && cl.internalGetCLState() == GPCLRegistryEntry.STATE_CL_DEACTIVATED && !acceptsActivation(cl)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Only the three known state bytes reach here, so the lookup cannot fail.
        return applyCLState(cl, CLState.ofByte(state).orElseThrow());
    }

    // GPC v2.3.1 Amd C 8.2: no policy implemented => accept; otherwise the applet's own verdict.
    private static boolean acceptsActivation(EngineRegistryEntry cl) {
        var sio = Simulator.current().getSystemSharedObject(cl.getAID(), GPCLSystem.GPCL_CL_APPLICATION_ACTIVATION_POLICY);
        return !(sio instanceof CLAppletActivationPolicy policy) || policy.acceptActivation();
    }

    // Route via the CRS (current holder of PRIVILEGE_CONTACTLESS_ACTIVATION; transferable, GPC v2.3.1 Amd C 7.1).
    // True iff the CRS approved; missing/wrong-SIO/throwing CRS all map to false (caller falls to 6982).
    private static boolean delegateToCRS(EngineRegistryEntry cl) {
        var crsEntry = RegistryPolicy.findHolder(Simulator.current().gp(), Privilege.ContactlessActivation).orElse(null);
        if (crsEntry == null) {
            return false;
        }
        var sim = Simulator.current();
        var sio = sim.getSystemSharedObject(crsEntry.getAID(), GPCLSystem.GPCL_CRS_APPLICATION);
        if (sio instanceof CRSApplication crs) {
            var requester = Simulator.current().currentApplication();
            if (requester == null) {
                return false;
            }
            try {
                return crs.processCLRequest(requester, cl, CLAppletEvent.EVENT_ACTIVATED);
            } catch (Exception e) {
                log.warn("CRS processCLRequest failed for {}", cl.getAID(), e);
            }
        } else if (sio != null) {
            log.warn("{} returned instead of CRSApplication", sio.getClass().getSimpleName());
        }
        return false;
    }

    public static byte applyCLState(EngineRegistryEntry cl, CLState newState) {
        if (cl.internalApplyCLState(newState.value)) {
            log.info("{} -> {}", cl.getAID(), newState);
            cl.bumpUpdateCounter();
            notifyContactlessEvent(cl, newState.event);
        }
        return cl.internalGetCLState();
    }

    // GPC v2.3.1 Amd C 8.3: the OPEN attempts an Application's Initial Contactless Activation State - its
    // own if set, else the OPEN-owned default - at first make-selectable and on unlock. OPEN-issued, so it
    // skips the cross-applet authorization gate that setCLState enforces.
    static byte applyInitial(EngineRegistryEntry cl) {
        return applyCLState(cl, cl.initial != null ? cl.initial : Simulator.current().gp().defaultInitial);
    }
}
