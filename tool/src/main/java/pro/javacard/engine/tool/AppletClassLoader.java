/*
 * Copyright 2025 Martin Paljak <martin@martinpaljak.net>
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

class AppletClassLoader extends URLClassLoader {
    private static final Logger log = LoggerFactory.getLogger(AppletClassLoader.class);

    AppletClassLoader() {
        super(new URL[0], AppletClassLoader.class.getClassLoader());
    }

    List<String> addApplet(Path file) throws IOException {
        if (Files.isDirectory(file)) {
            addURL(file.toUri().toURL());
            return locateApplets(file, this);
        }
        Path tmp = Files.createTempDirectory("applet");
        String name = file.getFileName().toString().toLowerCase();

        try (FileSystem fs = FileSystems.newFileSystem(file, (ClassLoader) null)) {
            Path src = name.endsWith(".cap") ?
                    fs.getPath("APPLET-INF", "classes") :
                    fs.getPath("/");

            if (Files.exists(src)) {
                Files.walk(src)
                        .filter(p -> p.toString().endsWith(".class"))
                        .forEach(p -> copy(p, tmp.resolve(src.relativize(p).toString())));
            } else {
                throw new FileNotFoundException("APPLET-INF/classes is missing from " + file.getFileName());
            }
        }
        // Add to classpath here, so that locateApplets would have access to loaded classes.
        addURL(tmp.toUri().toURL());
        log.trace("adding {}", tmp);
        return locateApplets(tmp, this);
    }

    private void copy(Path from, Path to) {
        try {
            Files.createDirectories(to.getParent());
            Files.copy(from, to);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static List<String> locateApplets(Path src, URLClassLoader cl) throws IOException {
        List<String> applets = new ArrayList<>();
        Files.walk(src)
                .filter(p -> p.toString().endsWith(".class"))
                .forEach(p -> {
                    if (InstallableAppletChecker.isValidApplet(p, cl)) {
                        String cls = src.relativize(p).toString().replace("/", ".");
                        applets.add(cls.substring(0, cls.length() - 6)); // bite off ".class"
                    }
                });
        return applets;
    }

    @Override
    public Class<?> loadClass(String name) throws ClassNotFoundException {
        log.trace("loadClass {}", name);
        return super.loadClass(name);
    }
}
