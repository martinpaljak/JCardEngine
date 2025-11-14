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

import com.licel.jcardsim.base.Simulator;
import org.objectweb.asm.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FaultInjectionInterceptor extends ClassVisitor {
    private static final Logger log = LoggerFactory.getLogger(FaultInjectionInterceptor.class);

    private String currentClassName;
    private boolean fieldsAdded = false;
    private boolean clinitExists = false;
    private boolean isInterface = false;

    public FaultInjectionInterceptor(ClassVisitor classVisitor) {
        super(Opcodes.ASM9, classVisitor);
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
        this.currentClassName = name;
        this.isInterface = (access & Opcodes.ACC_INTERFACE) != 0;
        super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor,
        String signature, String[] exceptions) {
        MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);

        log.trace("visitMethod called: class={}, method={}, isInterface={}", currentClassName, name, isInterface);

        // Don't instrument interfaces
        if (isInterface) {
            return mv;
        }

        // Check if <clinit> exists
        if (name.equals("<clinit>")) {
            clinitExists = true;
            // Wrap it to add our initialization at the beginning
            return new StaticInitializerWrapper(mv, currentClassName);
        }

        return new FaultInjectionMethodVisitor(mv, currentClassName);
    }

    @Override
    public void visitEnd() {
        // Don't add fields to interfaces
        if (isInterface) {
            super.visitEnd();
            return;
        }

        // Add static fields if not already added
        if (!fieldsAdded) {
            // Add boolean[] $faultFlips
            FieldVisitor fv1 = super.visitField(
                Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "$faultFlips",
                "[Z",
                null,
                null
            );
            if (fv1 != null) fv1.visitEnd();

            // Add int[] $faultIntFlips
            FieldVisitor fv2 = super.visitField(
                Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "$faultIntFlips",
                "[I",
                null,
                null
            );
            if (fv2 != null) fv2.visitEnd();

            // Only create <clinit> if it doesn't exist
            if (!clinitExists) {
                MethodVisitor mv = super.visitMethod(
                    Opcodes.ACC_STATIC,
                    "<clinit>",
                    "()V",
                    null,
                    null
                );
                if (mv != null) {
                    mv.visitCode();
                    injectFaultArrayInitialization(mv);
                    mv.visitInsn(Opcodes.RETURN);
                    mv.visitMaxs(1, 0);
                    mv.visitEnd();
                }
            }

            fieldsAdded = true;
        }
        super.visitEnd();
    }

    private void injectFaultArrayInitialization(MethodVisitor mv) {
        // $faultFlips = Simulator.getFaultFlipsArray();
        mv.visitMethodInsn(Opcodes.INVOKESTATIC,
            Simulator.class.getCanonicalName().replace(".", "/"),
            "getFaultFlipsArray",
            "()[Z",
            false);
        mv.visitFieldInsn(Opcodes.PUTSTATIC, currentClassName, "$faultFlips", "[Z");

        // $faultIntFlips = Simulator.getFaultIntFlipsArray();
        mv.visitMethodInsn(Opcodes.INVOKESTATIC,
            Simulator.class.getCanonicalName().replace(".", "/"),
            "getFaultIntFlipsArray",
            "()[I",
            false);
        mv.visitFieldInsn(Opcodes.PUTSTATIC, currentClassName, "$faultIntFlips", "[I");
    }

    private static class StaticInitializerWrapper extends MethodVisitor {
        private final String className;
        private boolean initialized = false;

        public StaticInitializerWrapper(MethodVisitor methodVisitor, String className) {
            super(Opcodes.ASM9, methodVisitor);
            this.className = className;
        }

        @Override
        public void visitCode() {
            super.visitCode();

            // Inject our initialization at the very beginning
            if (!initialized) {
                // $faultFlips = Simulator.getFaultFlipsArray();
                super.visitMethodInsn(Opcodes.INVOKESTATIC,
                    Simulator.class.getCanonicalName().replace(".", "/"),
                    "getFaultFlipsArray",
                    "()[Z",
                    false);
                super.visitFieldInsn(Opcodes.PUTSTATIC, className, "$faultFlips", "[Z");

                // $faultIntFlips = Simulator.getFaultIntFlipsArray();
                super.visitMethodInsn(Opcodes.INVOKESTATIC,
                    Simulator.class.getCanonicalName().replace(".", "/"),
                    "getFaultIntFlipsArray",
                    "()[I",
                    false);
                super.visitFieldInsn(Opcodes.PUTSTATIC, className, "$faultIntFlips", "[I");

                initialized = true;
            }
        }
    }

    private static class FaultInjectionMethodVisitor extends MethodVisitor {
        private final String className;
        private int currentLine = -1;

        public FaultInjectionMethodVisitor(MethodVisitor methodVisitor, String className) {
            super(Opcodes.ASM9, methodVisitor);
            this.className = className;
        }

        @Override
        public void visitLineNumber(int line, Label start) {
            this.currentLine = line;
            super.visitLineNumber(line, start);
        }

        @Override
        public void visitJumpInsn(int opcode, Label label) {
            // Only intercept conditional jumps
            if (isConditionalJump(opcode)) {
                injectConditionalFlip(opcode, label);
            } else {
                super.visitJumpInsn(opcode, label);
            }
        }

        private boolean isConditionalJump(int opcode) {
            return opcode == Opcodes.IFEQ || opcode == Opcodes.IFNE ||
                opcode == Opcodes.IFLT || opcode == Opcodes.IFGE ||
                opcode == Opcodes.IFGT || opcode == Opcodes.IFLE ||
                opcode == Opcodes.IF_ICMPEQ || opcode == Opcodes.IF_ICMPNE ||
                opcode == Opcodes.IF_ICMPLT || opcode == Opcodes.IF_ICMPGE ||
                opcode == Opcodes.IF_ICMPGT || opcode == Opcodes.IF_ICMPLE ||
                opcode == Opcodes.IF_ACMPEQ || opcode == Opcodes.IF_ACMPNE ||
                opcode == Opcodes.IFNULL || opcode == Opcodes.IFNONNULL;
        }

        private void injectConditionalFlip(int opcode, Label label) {
            log.trace("Injecting conditional flip {}:{} for opcode {}", className, currentLine, opcode);

            // Strategy: Evaluate condition to boolean, XOR with $faultFlips[line], then jump

            // Step 1: Evaluate original condition to boolean (0 or 1)
            Label trueLabel = new Label();
            Label evalEnd = new Label();

            super.visitJumpInsn(opcode, trueLabel);
            super.visitInsn(Opcodes.ICONST_0); // false
            super.visitJumpInsn(Opcodes.GOTO, evalEnd);
            super.visitLabel(trueLabel);
            super.visitInsn(Opcodes.ICONST_1); // true
            super.visitLabel(evalEnd);

            // Step 2: XOR with $faultFlips[currentLine]
            if (currentLine >= 0) {
                super.visitFieldInsn(Opcodes.GETSTATIC, className, "$faultFlips", "[Z");
                pushInt(currentLine);
                super.visitInsn(Opcodes.BALOAD); // Load boolean as 0 or 1
                super.visitInsn(Opcodes.IXOR);   // XOR: flips result if fault is enabled
            }

            // Step 3: Jump based on XORed result
            super.visitJumpInsn(Opcodes.IFNE, label);
        }

        @Override
        public void visitTableSwitchInsn(int min, int max, Label dflt, Label... labels) {
            log.trace("Injecting switch flip at {}:{}", className, currentLine);

            // Add $faultIntFlips[currentLine] to the switch value
            if (currentLine >= 0) {
                super.visitFieldInsn(Opcodes.GETSTATIC, className, "$faultIntFlips", "[I");
                pushInt(currentLine);
                super.visitInsn(Opcodes.IALOAD); // Load int offset
                super.visitInsn(Opcodes.IADD);   // value + offset
            }

            super.visitTableSwitchInsn(min, max, dflt, labels);
        }

        @Override
        public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
            log.trace("Injecting switch flip at {}:{}", className, currentLine);

            // Add $faultIntFlips[currentLine] to the switch value
            if (currentLine >= 0) {
                super.visitFieldInsn(Opcodes.GETSTATIC, className, "$faultIntFlips", "[I");
                pushInt(currentLine);
                super.visitInsn(Opcodes.IALOAD);
                super.visitInsn(Opcodes.IADD);
            }

            super.visitLookupSwitchInsn(dflt, keys, labels);
        }

        private void pushInt(int value) {
            if (value >= -1 && value <= 5) {
                super.visitInsn(Opcodes.ICONST_0 + value);
            } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
                super.visitIntInsn(Opcodes.BIPUSH, value);
            } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
                super.visitIntInsn(Opcodes.SIPUSH, value);
            } else {
                super.visitLdcInsn(value);
            }
        }
    }
}
