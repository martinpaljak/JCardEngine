// SPDX-FileCopyrightText: 2025 Martin Paljak
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.core;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class Faulty {

    private Faulty() {
    }

    public static String getSourceLine(String className, int lineNumber) {
        var sourcePath = className.replace('.', '/') + ".java";

        // 1. Try classpath (works if sources jar is on classpath)
        var resource = Thread.currentThread().getContextClassLoader().getResource(sourcePath);
        if (resource != null) {
            return readLine(resource, lineNumber);
        }

        // 2. Try standard Maven/Gradle source locations relative to CWD
        var sourceDirs = new String[]{
                "src/main/javacard",
                "src/main/java",
                "src/test/java"
        };

        for (var srcDir : sourceDirs) {
            var path = Path.of(srcDir, sourcePath);
            if (Files.exists(path)) {
                try {
                    var lines = Files.readAllLines(path);
                    if (lineNumber > 0 && lineNumber <= lines.size()) {
                        return lines.get(lineNumber - 1).trim();
                    }
                } catch (IOException e) {
                    // ignore, try next
                }
            }
        }

        // 3. Try to locate via class file location (IntelliJ often has parallel src/out
        // structure)
        try {
            var clazz = Class.forName(className);
            var classLocation = clazz.getProtectionDomain().getCodeSource().getLocation();
            if (classLocation != null) {
                var classRoot = Path.of(classLocation.toURI());
                var outDirs = new String[]{"target/classes", "target/test-classes", "build/classes/java/main"};
                for (var outDir : outDirs) {
                    var classRootStr = classRoot.toString();
                    if (classRootStr.contains(outDir)) {
                        var srcRoot = Path.of(classRootStr.replace(outDir, "src/main/java"));
                        var srcFile = srcRoot.resolve(sourcePath);
                        if (!Files.exists(srcFile)) {
                            srcRoot = Path.of(classRootStr.replace(outDir, "src/test/java"));
                            srcFile = srcRoot.resolve(sourcePath);
                        }
                        if (Files.exists(srcFile)) {
                            var lines = Files.readAllLines(srcFile);
                            if (lineNumber > 0 && lineNumber <= lines.size()) {
                                return lines.get(lineNumber - 1).trim();
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }

        return null;
    }

    private static String readLine(URL url, int lineNumber) {
        try (var reader = new BufferedReader(new InputStreamReader(url.openStream(), StandardCharsets.UTF_8))) {
            String line;
            var current = 0;
            while ((line = reader.readLine()) != null) {
                current++;
                if (current == lineNumber) {
                    return line.trim();
                }
            }
        } catch (IOException e) {
            // ignore
        }
        return null;
    }
}
