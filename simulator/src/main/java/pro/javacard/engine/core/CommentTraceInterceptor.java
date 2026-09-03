// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.core;

import com.licel.jcardsim.base.Simulator;
import org.objectweb.asm.Attribute;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pro.javacard.engine.core.CommentTraceAttribute.Line;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

// Logs every line of the CommentTrace attribute as the applet reaches the code line below it.
// The attribute is consumed, so the reloaded class does not carry it. A class without one was not
// built with the trace goal and is reported once, when it loads.
public final class CommentTraceInterceptor extends ClassVisitor {
    private static final Logger log = LoggerFactory.getLogger(CommentTraceInterceptor.class);
    private static final String SIMULATOR = Type.getInternalName(Simulator.class);

    private String name;
    private Map<Integer, List<Line>> byLine;

    public CommentTraceInterceptor(ClassVisitor classVisitor) {
        super(Opcodes.ASM9, classVisitor);
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
        super.visit(version, access, name, signature, superName, interfaces);
        this.name = name;
    }

    @Override
    public void visitEnd() {
        if (byLine == null) {
            log.warn("No CommentTrace attribute, class not built with the trace goal: {}", name);
        }
        super.visitEnd();
    }

    @Override
    public void visitAttribute(Attribute attribute) {
        if (attribute instanceof CommentTraceAttribute trace) {
            byLine = trace.lines.stream().collect(Collectors.groupingBy(Line::line));
            return;
        }
        super.visitAttribute(attribute);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
        if (byLine == null || byLine.isEmpty()) {
            return mv;
        }
        return new MethodVisitor(Opcodes.ASM9, mv) {
            private final Set<Integer> seen = new HashSet<>();

            // Loop heads whose backward jumps land after the once lines
            private final Map<Label, Label> redirect = new HashMap<>();

            @Override
            public void visitLineNumber(int line, Label start) {
                super.visitLineNumber(line, start);
                List<Line> lines = seen.add(line) ? byLine.getOrDefault(line, List.of()) : List.of();
                boolean once = false;
                for (Line l : lines) {
                    if (l.once()) {
                        trace(l);
                        once = true;
                    }
                }
                if (once) {
                    Label entry = new Label();
                    super.visitLabel(entry);
                    redirect.put(start, entry);
                }
                for (Line l : lines) {
                    if (!l.once()) {
                        trace(l);
                    }
                }
            }

            @Override
            public void visitJumpInsn(int opcode, Label label) {
                super.visitJumpInsn(opcode, redirect.getOrDefault(label, label));
            }

            private void trace(Line l) {
                super.visitLdcInsn(l.text());
                super.visitMethodInsn(Opcodes.INVOKESTATIC, SIMULATOR, "trace", "(Ljava/lang/String;)V", false);
            }
        };
    }
}
