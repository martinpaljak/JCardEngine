// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.core;

import apdu4j.core.CommandAPDU;
import apdu4j.prefs.Preferences;
import com.licel.jcardsim.utils.AIDUtil;
import org.testng.annotations.Test;
import pro.javacard.engine.CommentTrace;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.engine.testapplets.MemoryApplet;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static org.testng.Assert.*;

public class CommentTraceTest {
    private static final String AID_HEX = "D23300000077" + "4D454D2D3031" + "01";
    private static final Pattern TRACE = Pattern.compile("MemoryApplet\\.java:\\d+ (//.*)$");
    private static final String UNPROCESSED = "No CommentTrace attribute";

    private static List<String> stderr(Runnable body) {
        var buf = new ByteArrayOutputStream();
        var err = System.err;
        System.setErr(new PrintStream(buf, true, StandardCharsets.UTF_8));
        try {
            body.run();
        } finally {
            System.setErr(err);
        }
        return buf.toString(StandardCharsets.UTF_8).lines().toList();
    }

    // Install, SELECT, INS 43, then INS 42 query and GC in both report formats; returns the log
    private static List<String> run(Preferences prefs) {
        return stderr(() -> {
            var eng = new JavaCardEngine.Builder().preferences(prefs).build();
            var aid = AIDUtil.create(AID_HEX);
            eng.installApplet(aid, MemoryApplet.class);
            try (var bibo = eng.connect()) {
                assertEquals(bibo.transmit(AIDUtil.select(aid)).getSW(), 0x9000);
                assertEquals(bibo.transmit(new CommandAPDU(0x00, 0x43, 0x00, 0x00, 256)).getSW(), 0x9000);
                assertEquals(bibo.transmit(new CommandAPDU(0x00, 0x42, 0x00, 0x00, 256)).getSW(), 0x9000);
                assertEquals(bibo.transmit(new CommandAPDU(0x00, 0x42, 0x00, 0x01, 256)).getSW(), 0x9000);
                assertEquals(bibo.transmit(new CommandAPDU(0x00, 0x42, 0x01, 0x01, 256)).getSW(), 0x9000);
                assertEquals(bibo.transmit(new CommandAPDU(0x00, 0x42, 0x01, 0x00, 256)).getSW(), 0x9000);
            }
        });
    }

    private static List<String> traced(List<String> log) {
        return log.stream().map(TRACE::matcher).filter(Matcher::find).map(m -> m.group(1)).toList();
    }

    @Test
    public void commentLinesFollowExecution() throws IOException {
        // Silent without a filter, and no complaint either: the classes are not even inspected
        List<String> log = run(Preferences.of());
        assertEquals(traced(log), List.of());
        assertFalse(log.stream().anyMatch(l -> l.contains(UNPROCESSED)), log.toString());

        // "." logs every comment inside a method body, whatever its text: once above a loop, per iteration inside,
        // at the end of a void method on return; a comment above a class, field or method never fires
        log = run(Preferences.of(JavaCardEngine.TRACE_FILTER, "."));
        assertEquals(traced(log), List.of(
                "// step: Dispatch on INS",
                "// step: Dispatch on INS",
                "// step: P2 picks the report format",
                "// Two shorts per reading",
                "// Two shorts per reading",
                "// Two shorts per reading",
                "// step: Done",
                "// step: Dispatch on INS",
                "// step: P2 picks the report format",
                "// step: Three readings",
                "// step: One reading",
                "// step: One reading",
                "// step: One reading",
                "// step: Done",
                "// step: Dispatch on INS",
                "// step: P2 picks the report format",
                "// step: A refused request surfaces as SystemException",
                "// step: Done",
                "// step: Dispatch on INS",
                "// step: P2 picks the report format",
                "// step: Refuse when the runtime cannot delete objects",
                "// step: Done"));
        // Every test class went through the trace step, so none is reported
        assertFalse(log.stream().anyMatch(l -> l.contains(UNPROCESSED)), log.toString());

        // The filter regex is searched in the comment line; only matching lines are injected
        assertEquals(traced(run(Preferences.of(JavaCardEngine.TRACE_FILTER, "request"))), List.of(
                "// step: A refused request surfaces as SystemException"));

        // A malformed regex fails at engine construction
        assertThrows(PatternSyntaxException.class, () -> run(Preferences.of(JavaCardEngine.TRACE_FILTER, "(")));

        // A class that never went through the trace step is reported when a filter asks for the calls
        byte[] plain = Files.readAllBytes(Path.of("target/classes/pro/javacard/engine/core/CommentTraceAttribute$Line.class"));
        log = stderr(() -> BytecodeUtils.transform(plain, getClass().getClassLoader(), true));
        assertTrue(log.stream().anyMatch(l -> l.contains(UNPROCESSED + ", class not built with the trace goal: pro/javacard/engine/core/CommentTraceAttribute$Line")), log.toString());

        // Instrumenting the already instrumented test classes again changes nothing; the comment javac compiled away is reported
        Path classes = Path.of("target/test-classes");
        Path out = Files.createTempDirectory("traced");
        List<String> warnings = new ArrayList<>();
        try {
            CommentTrace.instrument(classes, List.of(Path.of("src/test/java")), out, StandardCharsets.UTF_8, warnings::add);
            Path applet = Path.of("pro/javacard/engine/testapplets/MemoryApplet.class");
            assertEquals(Files.readAllBytes(out.resolve(applet)), Files.readAllBytes(classes.resolve(applet)));
            // A processed class without body comments carries an empty attribute
            Path report = Path.of("pro/javacard/engine/testapplets/MemoryApplet$Report.class");
            assertEquals(Files.readAllBytes(out.resolve(report)), Files.readAllBytes(classes.resolve(report)));
            assertTrue(new String(Files.readAllBytes(classes.resolve(report)), StandardCharsets.ISO_8859_1).contains("CommentTrace"));
        } finally {
            try (var files = Files.walk(out)) {
                files.sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(File::delete);
            }
        }
        String dropped = "// step: Never compiled: no code follows it in its block, dropped";
        assertTrue(warnings.stream().anyMatch(w -> w.startsWith("src/test/java/pro/javacard/engine/testapplets/MemoryApplet.java:") && w.endsWith(dropped)), warnings.toString());
    }
}
