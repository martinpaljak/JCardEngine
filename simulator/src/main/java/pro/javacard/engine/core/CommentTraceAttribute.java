// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.core;

import org.objectweb.asm.Attribute;
import org.objectweb.asm.ByteVector;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;

import java.util.ArrayList;
import java.util.List;

// Class file attribute carrying the comment lines of a source file, keyed by the code line that follows them.
// Layout: u2 count, then per entry u2 line, u1 once and u2 constant pool index of the comment text.
public final class CommentTraceAttribute extends Attribute {
    public static final CommentTraceAttribute PROTOTYPE = new CommentTraceAttribute(List.of());

    // the u2 count, then per entry the offsets of u2 line, u1 once, u2 text index, and its size
    private static final int COUNT = 2, LINE = 0, ONCE = 2, TEXT = 3, ENTRY = 5;

    // once marks a comment written above a loop: logged when control reaches the loop, not per iteration
    public record Line(int line, String text, boolean once) {
    }

    public final List<Line> lines;

    public CommentTraceAttribute(List<Line> lines) {
        super("CommentTrace");
        this.lines = lines;
    }

    @Override
    protected Attribute read(ClassReader cr, int off, int len, char[] buf, int codeOff, Label[] labels) {
        List<Line> result = new ArrayList<>();
        int end = off + len;
        int n = cr.readUnsignedShort(off);
        off += COUNT;
        if (off + ENTRY * n != end) {
            throw new IllegalStateException("CommentTrace attribute length mismatch: " + len);
        }
        for (int i = 0; i < n; i++) {
            result.add(new Line(cr.readUnsignedShort(off + LINE), cr.readUTF8(off + TEXT, buf), cr.readByte(off + ONCE) != 0));
            off += ENTRY;
        }
        return new CommentTraceAttribute(result);
    }

    @Override
    protected ByteVector write(ClassWriter cw, byte[] code, int len, int maxStack, int maxLocals) {
        ByteVector v = new ByteVector();
        v.putShort(lines.size());
        for (Line l : lines) {
            v.putShort(l.line()).putByte(l.once() ? 1 : 0).putShort(cw.newUTF8(l.text()));
        }
        return v;
    }
}
