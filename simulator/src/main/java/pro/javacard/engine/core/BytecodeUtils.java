// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.core;

import org.objectweb.asm.Attribute;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.HashSet;

public final class BytecodeUtils {
    private static final Logger log = LoggerFactory.getLogger(BytecodeUtils.class);

    // trace injects the CommentTrace calls; without it the attribute passes through untouched
    public static byte[] transform(byte[] classBytes, ClassLoader classLoader, boolean trace) {
        ClassReader classReader = new ClassReader(classBytes);
        ClassWriter classWriter = new CustomClassWriter(classReader, ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES, classLoader);

        ClassVisitor chain = new MemoryAllocationInterceptor(classWriter);
        if (trace) {
            chain = new CommentTraceInterceptor(chain);
        }
        classReader.accept(new FaultInjectionInterceptor(chain), new Attribute[]{CommentTraceAttribute.PROTOTYPE}, 0);

        return classWriter.toByteArray();
    }

    // Custom ClassWriter that uses the correct ClassLoader
    static class CustomClassWriter extends ClassWriter {
        private final ClassLoader classLoader;

        public CustomClassWriter(ClassReader classReader, int flags, ClassLoader classLoader) {
            super(classReader, flags);
            this.classLoader = classLoader == null ? super.getClassLoader() : classLoader;
        }

        @Override
        protected ClassLoader getClassLoader() {
            return classLoader;
        }

        // Resolve common superclass without actually loading classes, but directly parsing class files.
        // This avoids ClassCircularityError when the parent implementation would call again transform() during COMPUTE_FRAMES.
        @Override
        protected String getCommonSuperClass(String type1, String type2) {
            var ancestors = new HashSet<String>();
            var current = type1;
            while (current != null) {
                ancestors.add(current);
                current = getSuperClass(current);
            }
            current = type2;
            while (current != null) {
                if (ancestors.contains(current)) {
                    return current;
                }
                current = getSuperClass(current);
            }
            return "java/lang/Object";
        }

        private String getSuperClass(String type) {
            if ("java/lang/Object".equals(type)) {
                return null;
            }
            try (InputStream is = classLoader.getResourceAsStream(type + ".class")) {
                if (is == null) {
                    throw new TypeNotPresentException(type.replace('/', '.'), null);
                }
                return new ClassReader(is).getSuperName();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }
}
