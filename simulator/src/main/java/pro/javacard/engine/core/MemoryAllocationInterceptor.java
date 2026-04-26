// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.core;

import com.licel.jcardsim.base.Simulator;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Utility class to intercept all "new byte[int]" calls and replace them with "Simulator.allocate(int)"
// This also sets the magic "jcardengine" flag to true.
public class MemoryAllocationInterceptor extends ClassVisitor {
    private static final Logger log = LoggerFactory.getLogger(MemoryAllocationInterceptor.class);

    public MemoryAllocationInterceptor(ClassVisitor classVisitor) {
        super(Opcodes.ASM9, classVisitor);
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
            if (opcode == Opcodes.NEWARRAY) {
                String method = null;
                String desc = null;
                if (operand == Opcodes.T_BYTE) {
                    method = "allocateBytes";
                    desc = "(I)[B";
                } else if (operand == Opcodes.T_BOOLEAN) {
                    method = "allocateBooleans";
                    desc = "(I)[Z";
                } else if (operand == Opcodes.T_SHORT) {
                    method = "allocateShorts";
                    desc = "(I)[S";
                }

                if (method != null) {
                    log.trace("Intercepting new array {}", method);
                    super.visitMethodInsn(Opcodes.INVOKESTATIC,
                            Simulator.class.getCanonicalName().replace(".", "/"),
                            method,
                            desc,
                            false);
                    return;
                }
            } 
            super.visitIntInsn(opcode, operand);
        }
    }
}
