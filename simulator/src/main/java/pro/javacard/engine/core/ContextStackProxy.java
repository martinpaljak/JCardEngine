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
package pro.javacard.engine.core;

import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.CardException;
import javacard.framework.CardRuntimeException;
import javacard.framework.Shareable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;

/**
 * Creates a dynamic proxy wrapper that intercepts method calls on Shareable interfaces to manage context switching.
 * Before each invocation, it pushes the server AID onto the context stack, executes the method, and pops it afterward.
 */
public class ContextStackProxy {
    private static final Logger log = LoggerFactory.getLogger(ContextStackProxy.class);

    public static Shareable wrap(AID serverAID, Deque<AID> contextStack, Shareable shareable) {
        var klass = shareable.getClass();
        var interfaces = allShareables(klass);
        return (Shareable) Proxy.newProxyInstance(
                klass.getClassLoader(),
                interfaces,
                (proxy, method, args) -> invoke(serverAID, contextStack, shareable, method, args)
        );
    }

    private static Object invoke(AID serverAID, Deque<AID> stack, Shareable shareable, Method method, Object[] args) throws Throwable {
        var caller = stack.peek();
        if (caller == null) {
            throw new IllegalStateException("Must be called from applet context");
        }
        log.info("Switching from {} to {}", AIDUtil.toString(caller), AIDUtil.toString(serverAID));
        stack.push(serverAID);
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
            stack.pop();
        }
    }

    private static Class<?>[] allShareables(Class<?> klass) {
        var interfaces = new HashSet<Class<?>>();
        Class<?> current = klass;
        while (!current.equals(Object.class)) {
            for (var iface : current.getInterfaces()) {
                if (Shareable.class.isAssignableFrom(iface)) {
                    log.debug("Adding {}", iface.getName());
                    Collections.addAll(interfaces, current.getInterfaces());
                }
            }
            current = current.getSuperclass();
        }
        return interfaces.toArray(Class[]::new);
    }
}
