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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

// Two instances of a Simulator() within one JVM should keep separate copies of Applet classes,
// to assure the isolation of static fields of applets in two different simulators.
// This increases the complexity by forcing to use reflection when calling into applet instance
// methods like select/process/deselect/uninstall, but increases the DWIM for developer.
public class IsolatingClassLoader extends URLClassLoader {
    private static final Logger log = LoggerFactory.getLogger(IsolatingClassLoader.class);

    private final List<String> mocks = new ArrayList<>();

    // Explicitly isolate from classpath
    public void isolate(String... packages) {
        for (String s : packages) {
            log.trace("Isolating {}", s);
            mocks.add(s);
        }
    }

    public IsolatingClassLoader(ClassLoader parent) {
        super(new URL[0], parent);
        // Add current classpath
        String classpath = System.getProperty("java.class.path");
        for (String path : classpath.split(System.getProperty("path.separator"))) {
            try {
                log.trace("Adding {}", path);
                addURL(Paths.get(path).toUri().toURL());
            } catch (Exception e) {
                log.warn("Could not load {}: {}", path, e.getMessage(), e);
            }
        }
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        // Force reload of target classes instead of delegating to parent
        if (isolate(name)) {
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
            return super.loadClass(name, resolve);
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
        if (isolate(name)) {
            try {
                // Load the class bytecode
                byte[] classBytes = getClassBytes(name);
                if (classBytes == null) {
                    log.error("Could not load {}", name);
                    // XXX: should probably still refer to super ?
                    throw new ClassNotFoundException(name);
                }

                // Transform the class to intercept byte array allocations
                byte[] transformedBytes = NewByteArrayInterceptor.transform(classBytes);
                return defineClass(name, transformedBytes, 0, transformedBytes.length, IsolatingClassLoader.class.getProtectionDomain());
            } catch (Exception e) {
                throw new ClassNotFoundException("Failed to load and transform class: " + name, e);
            }
        }
        return super.findClass(name);
    }

    private boolean isolate(String className) {
        return mocks.stream().anyMatch(className::startsWith);
    }
}