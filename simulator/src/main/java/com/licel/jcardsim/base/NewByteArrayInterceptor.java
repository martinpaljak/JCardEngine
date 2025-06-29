package com.licel.jcardsim.base;

import org.objectweb.asm.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Utility class to intercept all "new byte[int]" calls and replace them with "Simulator.allocate(int)"
// This also sets the magic "jcardsim" flag to true.
public class NewByteArrayInterceptor extends ClassVisitor {

    private static final Logger log = LoggerFactory.getLogger(NewByteArrayInterceptor.class);

    public NewByteArrayInterceptor(ClassVisitor classVisitor) {
        super(Opcodes.ASM9, classVisitor);
    }

    public static byte[] transform(byte[] classBytes) {
        ClassReader classReader = new ClassReader(classBytes);
        ClassWriter classWriter = new ClassWriter(classReader, ClassWriter.COMPUTE_FRAMES);
        NewByteArrayInterceptor interceptor = new NewByteArrayInterceptor(classWriter);

        classReader.accept(interceptor, 0);
        return classWriter.toByteArray();
    }

    // Feature: set the magic flag in any class to true
    // TODO: feature flag for this
    @Override
    public FieldVisitor visitField(int access, String name, String descriptor,
                                   String signature, Object value) {
        // Check if this is a "public static boolean jcardsim" field
        if (name.equals("jcardsim") &&
                descriptor.equals("Z") &&
                (access & Opcodes.ACC_PUBLIC) != 0 &&
                (access & Opcodes.ACC_STATIC) != 0) {
            log.info("Setting magic jcardsim field to true");
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