// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine;

import com.sun.source.tree.BlockTree;
import com.sun.source.tree.CaseTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.DoWhileLoopTree;
import com.sun.source.tree.EnhancedForLoopTree;
import com.sun.source.tree.ForLoopTree;
import com.sun.source.tree.LineMap;
import com.sun.source.tree.SwitchTree;
import com.sun.source.tree.Tree;
import com.sun.source.tree.WhileLoopTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreeScanner;
import com.sun.source.util.Trees;
import org.objectweb.asm.Attribute;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import pro.javacard.engine.core.CommentTraceAttribute;
import pro.javacard.engine.core.CommentTraceAttribute.Line;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.TreeSet;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

// Build step: records the comment lines inside method bodies in a class file attribute, keyed by the
// code line that follows each, for the engine to log as the applet reaches that line. A source file
// compiles to several class files (nested classes), so code lines are pooled per source file before a comment
// is attached to the nearest code line after it, wherever that line lives. A comment with no code below it
// in its own block, including code javac removed behind a constant false, is dropped and reported.
public final class CommentTrace {
    public static void main(String[] args) throws IOException {
        if (args.length < 3) {
            System.err.println("Usage: CommentTrace <classes> <out> <sources>...");
            System.exit(1);
        }
        instrument(Path.of(args[0]), Arrays.stream(args).skip(2).map(Path::of).toList(), Path.of(args[1]), StandardCharsets.UTF_8, System.err::println);
    }

    // Rewrites every class under classes into out, same package paths; out may equal classes
    public static void instrument(Path classes, List<Path> sources, Path out, Charset encoding, Consumer<String> warn) throws IOException {
        Map<Path, List<Path>> packages;
        try (Stream<Path> s = Files.walk(classes)) {
            packages = s.filter(p -> p.toString().endsWith(".class")).collect(Collectors.groupingBy(Path::getParent));
        }
        for (var e : packages.entrySet()) {
            Path pkg = classes.relativize(e.getKey());
            Map<Path, byte[]> bytes = new HashMap<>();
            Map<Path, String> sourceOf = new HashMap<>();
            Map<String, TreeSet<Integer>> code = new HashMap<>();
            for (Path file : e.getValue()) {
                bytes.put(file, Files.readAllBytes(file));
                sourceOf.put(file, collect(bytes.get(file), code));
            }
            Map<String, List<Line>> anchors = new HashMap<>();
            for (var c : code.entrySet()) {
                Path src = sources.stream().map(r -> r.resolve(pkg).resolve(c.getKey())).filter(Files::isRegularFile).findFirst()
                        .orElseThrow(() -> new IllegalStateException("No source file for " + pkg.resolve(c.getKey())));
                var ranges = scan(src, encoding);
                Path rel = Path.of("").toAbsolutePath().relativize(src.toAbsolutePath());
                anchors.put(c.getKey(), anchor(Files.readAllLines(src, encoding), ranges.getKey(), ranges.getValue(), c.getValue(), c.getKey(), m -> warn.accept(rel + ":" + m)));
            }
            for (Path file : e.getValue()) {
                Path target = out.resolve(classes.relativize(file));
                Files.createDirectories(target.getParent());
                Files.write(target, attach(bytes.get(file), anchors.getOrDefault(sourceOf.get(file), List.of())));
            }
        }
    }

    // Replaces the CommentTrace attribute of a class; empty when the source has no body comments
    private static byte[] attach(byte[] bytes, List<Line> lines) {
        ClassReader reader = new ClassReader(bytes);
        ClassWriter writer = new ClassWriter(reader, 0);
        reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
            @Override
            public void visitAttribute(Attribute attribute) {
                if (!(attribute instanceof CommentTraceAttribute)) {
                    super.visitAttribute(attribute);
                }
            }

            @Override
            public void visitEnd() {
                super.visitAttribute(new CommentTraceAttribute(lines));
                super.visitEnd();
            }
        }, new Attribute[]{CommentTraceAttribute.PROTOTYPE}, 0);
        return writer.toByteArray();
    }

    // Adds the LineNumberTable lines of one class to its source file's pool and returns the SourceFile name
    private static String collect(byte[] bytes, Map<String, TreeSet<Integer>> code) {
        var source = new String[1];
        new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public void visitSource(String s, String debug) {
                source[0] = s;
            }

            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                if (source[0] == null) {
                    throw new IllegalStateException("Class without SourceFile attribute, compile with -g");
                }
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitLineNumber(int line, Label start) {
                        code.computeIfAbsent(source[0], k -> new TreeSet<>()).add(line);
                    }
                };
            }
        }, ClassReader.SKIP_FRAMES);
        return source[0];
    }

    // Line ranges of blocks (method, initializer and statement bodies, switch cases) and of loop statements,
    // from javac's own parser
    static Map.Entry<List<int[]>, List<int[]>> scan(Path source, Charset encoding) throws IOException {
        JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
        List<int[]> blocks = new ArrayList<>();
        List<int[]> loops = new ArrayList<>();
        try (StandardJavaFileManager fm = javac.getStandardFileManager(null, null, encoding)) {
            JavacTask task = (JavacTask) javac.getTask(null, fm, null, List.of("-proc:none"), null, fm.getJavaFileObjects(source));
            SourcePositions positions = Trees.instance(task).getSourcePositions();
            for (CompilationUnitTree cu : task.parse()) {
                LineMap map = cu.getLineMap();
                new TreeScanner<Void, Void>() {
                    @Override
                    public Void visitBlock(BlockTree block, Void unused) {
                        blocks.add(range(block));
                        return super.visitBlock(block, unused);
                    }

                    // A case runs up to the next case label or the end of the switch
                    @Override
                    public Void visitSwitch(SwitchTree sw, Void unused) {
                        List<? extends CaseTree> cases = sw.getCases();
                        for (int i = 0; i < cases.size(); i++) {
                            int to = i + 1 < cases.size() ? range(cases.get(i + 1))[0] - 1 : range(sw)[1];
                            blocks.add(new int[]{range(cases.get(i))[0], to});
                        }
                        return super.visitSwitch(sw, unused);
                    }

                    @Override
                    public Void visitWhileLoop(WhileLoopTree loop, Void unused) {
                        loops.add(range(loop));
                        return super.visitWhileLoop(loop, unused);
                    }

                    @Override
                    public Void visitDoWhileLoop(DoWhileLoopTree loop, Void unused) {
                        loops.add(range(loop));
                        return super.visitDoWhileLoop(loop, unused);
                    }

                    @Override
                    public Void visitForLoop(ForLoopTree loop, Void unused) {
                        loops.add(range(loop));
                        return super.visitForLoop(loop, unused);
                    }

                    @Override
                    public Void visitEnhancedForLoop(EnhancedForLoopTree loop, Void unused) {
                        loops.add(range(loop));
                        return super.visitEnhancedForLoop(loop, unused);
                    }

                    private int[] range(Tree tree) {
                        return new int[]{(int) map.getLineNumber(positions.getStartPosition(cu, tree)), (int) map.getLineNumber(positions.getEndPosition(cu, tree))};
                    }
                }.scan(cu, null);
            }
        }
        return Map.entry(blocks, loops);
    }

    // Comment lines inside blocks, anchored to the nearest following code line within the innermost block;
    // a comment whose anchor sits in a loop that starts below it is logged once, on entry
    static List<Line> anchor(List<String> lines, List<int[]> blocks, List<int[]> loops, NavigableSet<Integer> code, String file, Consumer<String> warn) {
        List<Line> result = new ArrayList<>();
        for (int i = 0; i < lines.size(); i++) {
            int line = i + 1;
            String text = lines.get(i).trim();
            if (!text.startsWith("//")) {
                continue;
            }
            int end = blocks.stream().filter(b -> b[0] <= line && line <= b[1]).mapToInt(b -> b[1]).min().orElse(-1);
            if (end < 0) {
                continue;
            }
            Integer next = code.higher(line);
            if (next == null || next > end) {
                warn.accept(line + " " + text + ": no code follows it in its block, dropped");
                continue;
            }
            boolean once = loops.stream().anyMatch(l -> l[0] > line && l[0] <= next && next <= l[1]);
            result.add(new Line(next, file + ":" + line + " " + text, once));
        }
        return result;
    }
}
