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

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.InvocationHandlerAdapter;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

// Utility class to provide similarly shaped instance for a class from a different classloader.
// Used to access the isolated applet class via Applet superclass, including any known interfaces for "instanceof"
public class ReflectiveClassProxy {
    private static final Logger log = LoggerFactory.getLogger(ReflectiveClassProxy.class);

    // Assumes the abstract class is shared between classloaders
    public static <T> T proxy(Object targetInstance, Class<T> abstractClass) throws Exception {
        if (!abstractClass.isAssignableFrom(targetInstance.getClass())) {
            String msg = String.format("Target instance of type %s does not extend/implement %s", targetInstance.getClass().getName(), abstractClass.getName());
            throw new IllegalArgumentException(msg);
        }

        Class<?> targetClass = targetInstance.getClass();

        // WHAT: Get all interfaces implemented by the target instance
        // WHY: We want the proxy to "look like" the target for instanceof checks
        Class<?>[] targetInterfaces = targetClass.getInterfaces();

        // WHAT: Filter interfaces to only include ones visible in the abstract class's classloader
        // WHY: Avoid ClassNotFoundException when the proxy's classloader can't see target's interfaces
        List<Class<?>> visibleInterfaces = new ArrayList<>();
        ClassLoader proxyClassLoader = abstractClass.getClassLoader();

        for (Class<?> iface : targetInterfaces) {
            try {
                // Test if this interface is visible in the proxy's classloader
                Class<?> visibleInterface = proxyClassLoader.loadClass(iface.getName());
                visibleInterfaces.add(visibleInterface);
                // WHY: We need the interface Class object from the proxy's classloader,
                // not the target's classloader, for ByteBuddy to work properly
            } catch (ClassNotFoundException e) {
                log.warn("Ignoring implementation interface {}", iface.getSimpleName());
                // Interface not visible in proxy classloader - skip it
                // WHY: This prevents ClassNotFoundException during proxy creation
            }
        }

        // Build method matcher for abstract class + all visible interfaces
        ElementMatcher.Junction<MethodDescription> methodMatcher = ElementMatchers.isDeclaredBy(abstractClass);
        for (Class<?> iface : visibleInterfaces) {
            methodMatcher = methodMatcher.or(ElementMatchers.isDeclaredBy(iface));
        }

        DynamicType.Builder<? extends T> builder = new ByteBuddy()
                .subclass(abstractClass);

        // WHAT: Dynamically implement all visible interfaces
        // WHY: This makes "instanceof ExtendedLength" return true if target implements it
        if (!visibleInterfaces.isEmpty()) {
            builder = builder.implement(visibleInterfaces.toArray(new Class<?>[0]));
        }

        Class<? extends T> proxyClass = builder
                .method(methodMatcher)
                // WHAT: Intercept methods from abstract class + all implemented interfaces
                // WHY: All interface methods need to be delegated to the target instance

                .intercept(InvocationHandlerAdapter.of((proxy, method, args) -> {
                    try {
                        Method targetMethod = targetClass.getMethod(method.getName(), method.getParameterTypes());
                        return targetMethod.invoke(targetInstance, args);
                    } catch (InvocationTargetException e) {
                        Throwable cause = e.getCause();
                        if (cause == null) {
                            // Shouldn't happen, but be defensive
                            throw e;
                        }
                        // re-throw the original exception
                        throw cause;
                    }
                }))
                .make()
                .load(abstractClass.getClassLoader())
                .getLoaded();

        return proxyClass.getDeclaredConstructor().newInstance();
    }
}
