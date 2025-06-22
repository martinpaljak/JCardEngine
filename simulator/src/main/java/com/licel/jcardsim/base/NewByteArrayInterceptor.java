package com.licel.jcardsim.base;

import org.objectweb.asm.*;

// Utility class to intercept all "new byte[int]" calls and replace them with "Simulator.allocate(int)"
public class NewByteArrayInterceptor extends ClassVisitor {

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
                super.visitMethodInsn(Opcodes.INVOKESTATIC,
                        "com/licel/jcardsim/base/Simulator",
                        "allocate",
                        "(I)[B",
                        false);
            } else {
                super.visitIntInsn(opcode, operand);
            }
        }
    }
}