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

import org.objectweb.asm.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Utility class to intercept all "new byte[int]" calls and replace them with "Simulator.allocate(int)"
// This also sets the magic "jcardengine" flag to true.
public class NewByteArrayInterceptor extends ClassVisitor {

    // Custom ClassWriter that uses the correct ClassLoader
    private static class CustomClassWriter extends ClassWriter {
        private final ClassLoader classLoader;

        public CustomClassWriter(ClassReader classReader, int flags, ClassLoader classLoader) {
            super(classReader, flags);
            this.classLoader = classLoader;
        }

        @Override
        protected ClassLoader getClassLoader() {
            return classLoader != null ? classLoader : super.getClassLoader();
        }
    }

    private static final Logger log = LoggerFactory.getLogger(NewByteArrayInterceptor.class);

    public NewByteArrayInterceptor(ClassVisitor classVisitor) {
        super(Opcodes.ASM9, classVisitor);
    }

    public static byte[] transform(byte[] classBytes, ClassLoader classLoader) {
        ClassReader classReader = new ClassReader(classBytes);
        // NOTE: java.lang.ClassCircularityError if COMPUTE_FRAMES
        ClassWriter classWriter = new CustomClassWriter(classReader, ClassWriter.COMPUTE_MAXS, classLoader);
        NewByteArrayInterceptor interceptor = new NewByteArrayInterceptor(classWriter);

        classReader.accept(interceptor, 0);
        return classWriter.toByteArray();
    }

    // Feature: set the magic flag in any class to true
    // TODO: feature flag for this
    @Override
    public FieldVisitor visitField(int access, String name, String descriptor,
                                   String signature, Object value) {
        // Check if this is a "public static boolean jcardengine" field
        if (name.equals("jcardengine") &&
                descriptor.equals("Z") &&
                (access & Opcodes.ACC_PUBLIC) != 0 &&
                (access & Opcodes.ACC_STATIC) != 0) {
            log.info("Setting magic jcardengine field to true");
            // Force the value to true (represented as 1 for boolean)
            return super.visitField(access, name, descriptor, signature, 1);
        }
        return super.visitField(access, name, descriptor, signature, value);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor,
                                     String signature, String[] exceptions) {
        MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
        return new ByteArrayMethodVisitor(mv);
    }

    private static class ByteArrayMethodVisitor extends MethodVisitor {

        public ByteArrayMethodVisitor(MethodVisitor methodVisitor) {
            super(Opcodes.ASM9, methodVisitor);
        }

        @Override
        public void visitIntInsn(int opcode, int operand) {
            if (opcode == Opcodes.NEWARRAY && operand == Opcodes.T_BYTE) {
                // Replace single-dimension byte array creation with call to allocate method
                // Stack before: [size]
                // Stack after: [byte[]]
                log.trace("Intercepting \"new byte[]\"");
                super.visitMethodInsn(Opcodes.INVOKESTATIC,
                        Simulator.class.getCanonicalName().replace(".", "/"),
                        "allocate",
                        "(I)[B",
                        false);
            } else {
                super.visitIntInsn(opcode, operand);
            }
        }
    }
}