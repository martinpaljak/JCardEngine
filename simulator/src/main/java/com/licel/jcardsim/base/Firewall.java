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
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Supplier;

public class Firewall {
    private static final Logger log = LoggerFactory.getLogger(Firewall.class);
    private final Shareable shareable;
    private final Shareable firewalled;

    private final Supplier<AID> getter;
    private final Consumer<AID> setter;
    private final Deque<AID> stack;
    private final AID serverAID;

    public Firewall(AID server, Supplier<AID> current, Consumer<AID> currentSetter, Deque<AID> stack, Shareable shareable) {
        Objects.requireNonNull(shareable);

        var klass = shareable.getClass();
        var interfaces = allShareables(klass);

        this.shareable = shareable;
        this.getter = current;
        this.setter = currentSetter;
        this.stack = stack;
        this.serverAID = server;
        this.firewalled = (Shareable) Proxy.newProxyInstance(klass.getClassLoader(), interfaces, Firewall.this::invoke);
    }

    static Class<?>[] allShareables(Class<?> klass) {
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

    Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        var current = getter.get();
        log.info("Switching from {} to {}", AIDUtil.toString(current), AIDUtil.toString(serverAID));
        stack.push(current);
        try {
            setter.accept(serverAID);
            return method.invoke(shareable, args);
        } catch (InvocationTargetException e) {
            var real = e.getTargetException();
            if (real instanceof CardException ce) {
                log.info("{} from shareable: {}", real.getClass().getSimpleName(), ce.getReason());
            } else if (real instanceof CardRuntimeException cre) {
                log.info("{} from shareable: {}", real.getClass().getSimpleName(), cre.getReason());
            } else {
                log.info("{} from shareable", real.getClass().getSimpleName());
            }
            throw real;
        } finally {
            setter.accept(stack.pop());
        }
    }

    public Shareable getShareable() {
        return firewalled;
    }
}
