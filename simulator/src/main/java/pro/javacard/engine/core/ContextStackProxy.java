// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.core;

import javacard.framework.CardException;
import javacard.framework.CardRuntimeException;
import javacard.framework.Shareable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.engine.globalplatform.EngineRegistryEntry;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;

// Wraps a Shareable in a dynamic proxy that pushes the server entry onto the context stack for each call.
public class ContextStackProxy {
    private static final Logger log = LoggerFactory.getLogger(ContextStackProxy.class);

    public static Shareable wrap(EngineRegistryEntry server, Deque<EngineRegistryEntry> stack, Shareable shareable) {
        return wrap0(server, stack, shareable, false);
    }

    // Platform-initiated wrap (CRS/OPEN caller): clears the applet stack first, so the callee runs with
    // no previous applet context and getPreviousContextAID() returns null.
    public static Shareable wrapPlatform(EngineRegistryEntry server, Deque<EngineRegistryEntry> stack, Shareable shareable) {
        return wrap0(server, stack, shareable, true);
    }

    private static Shareable wrap0(EngineRegistryEntry server, Deque<EngineRegistryEntry> stack, Shareable shareable, boolean platform) {
        var klass = shareable.getClass();
        return (Shareable) Proxy.newProxyInstance(
                klass.getClassLoader(),
                allShareables(klass),
                (proxy, method, args) -> invoke(server, stack, shareable, method, args, platform)
        );
    }

    private static Object invoke(EngineRegistryEntry server, Deque<EngineRegistryEntry> stack, Shareable shareable, Method method, Object[] args, boolean platform) throws Throwable {
        Deque<EngineRegistryEntry> saved = null;
        if (platform) {
            log.info("Switching from <platform> to {}", server.getAID());
            // Suspend the caller stack: the callee sees only [server].
            saved = new ArrayDeque<>(stack);
            stack.clear();
        } else {
            var caller = stack.peek();
            if (caller == null) {
                throw new IllegalStateException("Must be called from applet context");
            }
            log.info("Switching context: {} -> {}", caller.getAID(), server.getAID());
        }
        stack.push(server);
        try {
            return method.invoke(shareable, args);
        } catch (InvocationTargetException e) {
            var real = e.getTargetException();
            if (real instanceof CardException ce) {
                log.warn("{} from shareable: {}", real.getClass().getSimpleName(), ce.getReason());
            } else if (real instanceof CardRuntimeException cre) {
                log.warn("{} from shareable: {}", real.getClass().getSimpleName(), cre.getReason());
            } else {
                log.warn("{} from shareable", real.getClass().getSimpleName());
            }
            throw real;
        } finally {
            if (platform) {
                stack.clear();
                stack.addAll(saved);
            } else {
                stack.pop();
            }
        }
    }

    private static Class<?>[] allShareables(Class<?> klass) {
        var interfaces = new HashSet<Class<?>>();
        Class<?> current = klass;
        while (current != null && !current.equals(Object.class)) {
            for (var iface : current.getInterfaces()) {
                if (Shareable.class.isAssignableFrom(iface)) {
                    log.debug("Adding {}", iface.getName());
                    interfaces.add(iface);
                }
            }
            current = current.getSuperclass();
        }
        return interfaces.toArray(Class[]::new);
    }
}
