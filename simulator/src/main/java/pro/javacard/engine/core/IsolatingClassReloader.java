// SPDX-FileCopyrightText: 2025 Martin Paljak
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureClassLoader;
import java.util.HashSet;
import java.util.Set;

/**
 * A custom class loader that creates isolated copies of specified package classes to prevent sharing of static fields
 * between simulator instances. Classes matching registered isolation patterns are loaded and bytecode-transformed
 * independently instead of being delegated to the parent class loader, ensuring each simulator instance has its own
 * class definitions.
 */
public final class IsolatingClassReloader extends SecureClassLoader {
    private static final Logger log = LoggerFactory.getLogger(IsolatingClassReloader.class);

    private final Set<String> isolated = new HashSet<>();

    public Class<?> reloadAndIsolate(Class<?> clazz) throws ClassNotFoundException {
        // Add package to isolated list
        isolated.add(clazz.getPackageName());

        // Re-load class
        return loadClass(clazz.getName(), false);
    }

    public IsolatingClassReloader(ClassLoader parent) {
        super("isolating", parent);
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        log.trace("Loading class {}", name);
        // Force reload of target classes instead of delegating to parent
        if (isolated.contains(pkgname(name))) {
            Class<?> clazz = findLoadedClass(name);
            if (clazz == null) {
                log.trace("{} isolating {}", System.identityHashCode(this), name);
                clazz = findClass(name);
            } else {
                log.trace("{} re-using  {}", System.identityHashCode(this), name);
            }
            if (resolve) {
                resolveClass(clazz);
            }
            return clazz;
        } else {
            // Default behaviour is to try the parent loader first, and then this
            var r = super.loadClass(name, resolve);
            log.trace("{} loaded from {}", name, getParent().getName());
            return r;
        }
    }

    private byte[] getClassBytes(String name) throws IOException {
        String path = name.replace('.', '/') + ".class";
        try (InputStream is = getResourceAsStream(path)) {
            if (is == null) {
                return null;
            }
            return is.readAllBytes();
        }
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        try {
            // Get the original class
            var orig = getParent().loadClass(name);
            log.trace("{} defined in {}", name, orig.getProtectionDomain().getCodeSource().getLocation());

            // Load the class bytecode
            byte[] classBytes = getClassBytes(name);
            if (classBytes == null) {
                log.error("Could not load bytecode of {}", name);
                throw new ClassNotFoundException("Could not re-load bytecode for " + name + " from " + getParent().getName());
            }
            log.trace("Transforming {}", name);
            // Transform the class to intercept byte array allocations
            byte[] transformedBytes = BytecodeUtils.transform(classBytes, this);
            return defineClass(name, transformedBytes, 0, transformedBytes.length, orig.getProtectionDomain());
        } catch (Exception e) {
            throw new ClassNotFoundException("Failed to load and transform class: " + name, e);
        }
    }

    public static String pkgname(String className) {
        if (className == null || className.isEmpty()) {
            return "";
        }
        int lastDot = className.lastIndexOf('.');
        if (lastDot == -1) {
            return "";
        }
        return className.substring(0, lastDot);
    }
}
