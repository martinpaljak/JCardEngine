// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.tool;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

// Little customisation for a classloader that can look into .cap files.
public final class AppletClassLoader extends URLClassLoader {
    private static final Logger log = LoggerFactory.getLogger(AppletClassLoader.class);

    public AppletClassLoader() {
        // Implicit parent
        super("applet", new URL[0], AppletClassLoader.class.getClassLoader());
    }

    // Add the specified path to the classloader, and return detected Applet classes
    public List<String> addApplet(Path file) throws IOException {
        // Option one: points to a folder.
        if (Files.isDirectory(file)) {
            addURL(file.toUri().toURL());
            return locateApplets(file);
        }
        // Option two: points to a file (.jar or .cap)
        Path tmp = Files.createTempDirectory("applet");
        Path filename = file.getFileName();
        if (filename == null) {
            throw new FileNotFoundException("Not a file: " + file);
        }
        String name = filename.toString().toLowerCase();

        try (FileSystem fs = FileSystems.newFileSystem(file)) {
            // Look into .cap structure or assume plain .jar
            Path src = name.endsWith(".cap") ? fs.getPath("APPLET-INF", "classes") : fs.getPath("/");

            if (!Files.exists(src)) {
                throw new FileNotFoundException("APPLET-INF/classes is missing from " + file.getFileName());
            }
            // Copy to temporary folder
            try (var s = Files.walk(src)) {
                s.filter(p -> p.toString().endsWith(".class")).forEach(p -> copy(p, tmp.resolve(src.relativize(p).toString())));
            }
        }
        // Add to classpath here, so that locateApplets would have access to loaded classes.
        addURL(tmp.toUri().toURL());
        log.trace("adding {}", tmp);
        return locateApplets(tmp);
    }

    private void copy(Path from, Path to) {
        try {
            Path parent = to.getParent();
            if (parent == null) {
                throw new FileNotFoundException("No parent directory: " + to);
            }
            Files.createDirectories(parent);
            Files.copy(from, to);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private List<String> locateApplets(Path src) throws IOException {
        List<String> applets = new ArrayList<>();
        try (var s = Files.walk(src)) {
            s.filter(p -> p.toString().endsWith(".class")).forEach(p -> {
                if (InstallableAppletChecker.isValidApplet(p, this)) {
                    String cls = src.relativize(p).toString().replaceAll("[/\\\\]", ".");
                    applets.add(cls.substring(0, cls.length() - ".class".length())); // bite off ".class"
                }
            });
        }
        return applets;
    }
}
