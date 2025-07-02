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

import com.licel.jcardsim.base.InstallSpec;
import com.licel.jcardsim.base.Simulator;
import javacard.framework.Applet;
import javacard.framework.SystemException;
import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import org.bouncycastle.util.encoders.Hex;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.jline.utils.NonBlockingReader;
import pro.javacard.capfile.CAPFile;
import pro.javacard.engine.adapters.AbstractTCPAdapter;
import pro.javacard.engine.adapters.JCSDKServer;
import pro.javacard.engine.adapters.VSmartCardClient;
import pro.javacard.engine.core.JavaCardEngine;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.spi.FileSystemProvider;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class JCardTool {
    // While Simulator interface has an ATR method, we don't really handle it on that level
    // The only relation would be GPSystem.setATRHistBytes(). So for now the ATR can be set freely
    // for adapters.
    static final String DEFAULT_ATR_HEX = "3B80800101";
    static final byte[] DEFAULT_ATR = Hex.decode(DEFAULT_ATR_HEX);

    static OptionParser parser = new OptionParser();

    // Generic options
    static OptionSpec<Void> OPT_HELP = parser.acceptsAll(Arrays.asList("h", "help"), "Show this help").forHelp();
    static OptionSpec<Void> OPT_VERSION = parser.acceptsAll(Arrays.asList("V", "version"), "Show version");
    static OptionSpec<Void> OPT_CONTROL = parser.acceptsAll(Arrays.asList("c", "control"), "Start control interface");
    static OptionSpec<Void> OPT_EXPOSED = parser.acceptsAll(Arrays.asList("exposed"), "Use exposed mode");

    // VSmartCard options
    static OptionSpec<Void> OPT_VSMARTCARD = parser.accepts("vsmartcard", "Run a VSmartCard client");
    static OptionSpec<Integer> OPT_VSMARTCARD_PORT = parser.accepts("vsmartcard-port", "VSmartCard port").withRequiredArg().ofType(Integer.class).defaultsTo(VSmartCardClient.DEFAULT_VSMARTCARD_PORT);
    static OptionSpec<String> OPT_VSMARTCARD_HOST = parser.accepts("vsmartcard-host", "VSmartCard host").withRequiredArg().ofType(String.class).defaultsTo(VSmartCardClient.DEFAULT_VSMARTCARD_HOST);
    static OptionSpec<String> OPT_VSMARTCARD_ATR = parser.accepts("vsmartcard-atr", "VSmartCard ATR").withRequiredArg().ofType(String.class);
    static OptionSpec<String> OPT_VSMARTCARD_PROTOCOL = parser.accepts("vsmartcard-protocol", "VSmartCard protocol").withRequiredArg().ofType(String.class).defaultsTo("*");

    // Oracle options
    static OptionSpec<Void> OPT_JCSDK = parser.accepts("jcsdk", "Run a JCSDK server");
    static OptionSpec<Integer> OPT_JCSDK_PORT = parser.accepts("jcsdk-port", "port to listen on").withRequiredArg().ofType(Integer.class).defaultsTo(JCSDKServer.DEFAULT_JCSDK_PORT);
    static OptionSpec<String> OPT_JCSDK_HOST = parser.accepts("jcsdk-host", "host to listen on").withRequiredArg().ofType(String.class).defaultsTo(JCSDKServer.DEFAULT_JCSDK_HOST);
    static OptionSpec<String> OPT_JCSDK_ATR = parser.accepts("jcsdk-atr", "ATR to report").withRequiredArg().ofType(String.class);
    static OptionSpec<String> OPT_JCSDK_PROTOCOL = parser.accepts("jcsdk-protocol", "Protocol to use towards simulator").withRequiredArg().ofType(String.class).defaultsTo("*");

    // Generic ATR override.
    static OptionSpec<String> OPT_ATR = parser.accepts("atr", "ATR to use (hex)").withRequiredArg().ofType(String.class).defaultsTo(DEFAULT_ATR_HEX);

    // .cap/.jar files to load
    static OptionSpec<File> toLoad = parser.nonOptions("path to .cap or .jar or classes directory").ofType(File.class);

    static OptionSpec<String> OPT_APPLET = parser.accepts("applet", "Applet to install").withRequiredArg().ofType(String.class);
    static OptionSpec<String> OPT_PARAMS = parser.accepts("params", "Installation parameters").withRequiredArg().ofType(String.class);
    static OptionSpec<String> OPT_AID = parser.accepts("aid", "Applet AID").withRequiredArg().ofType(String.class);

    // Class loader for .jar/.cap/classes
    static final AppletClassLoader loader = new AppletClassLoader();

    public static void main(String[] args) {
        String version = JCardTool.class.getPackage().getImplementationVersion();

        try {
            OptionSet options = parser.parse(args);

            if (options.has(OPT_VERSION)) {
                System.out.println("JCardEngine v" + version);
                return;
            }

            if (options.has(OPT_HELP) || args.length == 0) {
                parser.printHelpOn(System.out);
                return;
            }

            if (options.nonOptionArguments().isEmpty()) {
                System.err.println("Missing applets. Check --help");
                System.exit(2);
            }

            Set<String> availableApplets = new TreeSet<>();
            Map<String, byte[]> defaultAID = new HashMap<>();

            // Load non-options as applets & classes
            for (File f : options.valuesOf(toLoad)) {
                Path p = f.toPath();

                if (Files.isRegularFile(p) && p.getFileName().toString().endsWith(".cap")) {
                    CAPFile cap = CAPFile.fromFile(p);
                    for (Map.Entry<pro.javacard.capfile.AID, String> app : cap.getApplets().entrySet()) {
                        defaultAID.put(app.getValue(), app.getKey().getBytes());
                    }
                }
                availableApplets.addAll(loader.addApplet(p));
            }

            List<InstallSpec> spec = new ArrayList<>();

            if (availableApplets.isEmpty()) {
                System.err.println("No applets found");
                System.exit(1);
            } else if (options.has(OPT_APPLET)) {
                Class<? extends Applet> applet = requireExtendsApplet(loader.loadClass(options.valueOf(OPT_APPLET)));
                final byte[] aid;
                if (!options.has(OPT_AID) && defaultAID.containsKey(options.valueOf(OPT_APPLET))) {
                    aid = defaultAID.get(options.valueOf(OPT_APPLET));
                } else {
                    aid = Hex.decode(options.valueOf(OPT_AID));
                }
                byte[] params = options.has(OPT_PARAMS) ? Hex.decode(options.valueOf(OPT_PARAMS)) : null;
                spec.add(InstallSpec.of(aid, applet, params));
            } else if (availableApplets.size() == 1) {
                String klass = availableApplets.iterator().next();
                Class<? extends Applet> applet = requireExtendsApplet(loader.loadClass(klass));
                final byte[] aid;
                if (!options.has(OPT_AID) && defaultAID.containsKey(klass)) {
                    aid = defaultAID.get(klass);
                } else {
                    aid = Hex.decode(options.valueOf(OPT_AID));
                }
                byte[] params = options.has(OPT_PARAMS) ? Hex.decode(options.valueOf(OPT_PARAMS)) : null;
                spec.add(InstallSpec.of(aid, applet, params));
            } else {
                System.err.println("Multiple applets found, use --applet");
                for (String applet : availableApplets) {
                    System.err.println("- " + applet);
                }
                System.exit(1);
            }

            // Set up simulator. Right now a sample thingy
            JavaCardEngine sim = JavaCardEngine.create().exposed(true);
            for (InstallSpec s: spec) {
                sim.installApplet(s.getAID(), s.getAppletClass(), s.getParamters());
            }
            ExecutorService exec = Executors.newFixedThreadPool(3);

            List<AbstractTCPAdapter> adapters = new ArrayList<>();

            if (options.has(OPT_VSMARTCARD) || options.has(OPT_VSMARTCARD_PORT) || options.has(OPT_VSMARTCARD_HOST) || options.has(OPT_VSMARTCARD_PROTOCOL) || options.has(OPT_VSMARTCARD_ATR)) {
                int port = options.valueOf(OPT_VSMARTCARD_PORT);
                String host = options.valueOf(OPT_VSMARTCARD_HOST);
                AbstractTCPAdapter adapter = new VSmartCardClient(host, port, sim);
                if (options.has(OPT_ATR)) {
                    adapter = adapter.withATR(Hex.decode(options.valueOf(OPT_ATR)));
                }
                if (options.has(OPT_VSMARTCARD_ATR)) {
                    adapter = adapter.withATR(Hex.decode(options.valueOf(OPT_VSMARTCARD_ATR)));
                }
                if (options.has(OPT_VSMARTCARD_PROTOCOL)) {
                    adapter = adapter.withProtocol(options.valueOf(OPT_VSMARTCARD_PROTOCOL));
                }
                adapter = adapter.withTimeout(Duration.ofSeconds(1));
                adapters.add(adapter);
            }

            if (options.has(OPT_JCSDK) || options.has(OPT_JCSDK_PORT) || options.has(OPT_JCSDK_HOST) || options.has(OPT_JCSDK_PROTOCOL) || options.has(OPT_JCSDK_ATR)) {
                int port = options.valueOf(OPT_JCSDK_PORT);
                String host = options.valueOf(OPT_JCSDK_HOST);
                AbstractTCPAdapter adapter = new JCSDKServer(host, port, sim);

                if (options.has(OPT_ATR)) {
                    adapter = adapter.withATR(Hex.decode(options.valueOf(OPT_ATR)));
                }
                if (options.has(OPT_JCSDK_ATR)) {
                    adapter = adapter.withATR(Hex.decode(options.valueOf(OPT_JCSDK_ATR)));
                }
                if (options.has(OPT_JCSDK_PROTOCOL)) {
                    adapter = adapter.withProtocol(options.valueOf(OPT_JCSDK_PROTOCOL));
                }
                adapters.add(adapter);
            }

            // Trap ctrl-c and similar signals
            Thread shutdownThread = new Thread(() -> {
                System.err.println("Ctrl-C, quitting JCardEngine");
                exec.shutdownNow();
            });

            if (adapters.isEmpty()) {
                System.err.println("Use one of --vsmartcard or --jcsdk");
                System.exit(2);
            }

            Runtime.getRuntime().addShutdownHook(shutdownThread);
            if (options.has(OPT_CONTROL)) {
                adapters.forEach(exec::submit);

                // This seems to be the trick to keep ctrl-c working with keypress detection
                TerminalBuilder tb = TerminalBuilder.builder().nativeSignals(false);
                try (Terminal terminal = tb.build()) {
                    terminal.enterRawMode();
                    NonBlockingReader reader = terminal.reader();
                    while (!Thread.currentThread().isInterrupted()) {
                        int c = reader.read();
                        if (c == 27 || c == 113) {
                            // esc or q
                            System.err.println("Quit.");
                            break;
                        } else if (c == 116) {
                            // tap
                            System.err.println("Triggering a fresh tap: boop!");
                            adapters.forEach(AbstractTCPAdapter::tap);
                        } else {
                            // print help
                            System.err.println("Press 't' to trigger tap, 'q' or Esc to quit.");
                        }
                    }
                }
            } else {
                // This blocks until all are done, unless ctrl-c is hit
                exec.invokeAll(adapters);
            }

            Runtime.getRuntime().removeShutdownHook(shutdownThread);
            exec.shutdownNow();
            while (!exec.isTerminated()) {
                if (exec.awaitTermination(1, TimeUnit.MINUTES))
                    break;
            }
            System.err.println("Thank you for using JCardEngine v" + version + "!");
        } catch (OptionException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            System.err.println(e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(2);
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

    @SuppressWarnings("unchecked")
    private static Class<? extends Applet> requireExtendsApplet(Class<?> cls) {
        System.out.println("Validating " + cls.getName());
        if (!Applet.class.isAssignableFrom(cls)) {
            throw new SystemException(SystemException.ILLEGAL_VALUE);
        }
        return (Class<? extends Applet>) cls;
    }

    static class AppletClassLoader extends URLClassLoader {
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
    }
}