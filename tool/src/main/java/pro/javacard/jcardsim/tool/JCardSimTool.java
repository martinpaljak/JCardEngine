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
package pro.javacard.jcardsim.tool;

import com.licel.jcardsim.base.CardInterface;
import javacard.framework.Applet;
import javacard.framework.SystemException;
import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.capfile.CAPFile;
import pro.javacard.jcardsim.adapters.JCSDKServer;
import pro.javacard.jcardsim.adapters.RemoteTerminalProtocol;
import pro.javacard.jcardsim.adapters.VSmartCard;
import pro.javacard.jcardsim.core.InstallSpec;
import pro.javacard.jcardsim.core.ThreadedSimulator;

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
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public class JCardSimTool {
    private static final Logger log = LoggerFactory.getLogger(JCardSimTool.class);

    static OptionParser parser = new OptionParser();

    // Main options
    static OptionSpec<Void> OPT_HELP = parser.acceptsAll(Arrays.asList("h", "help"), "Show this help").forHelp();

    // VSmartCard options
    static OptionSpec<Void> OPT_VSMARTCARD = parser.accepts("vsmartcard", "Run a VSmartCard client");
    static OptionSpec<Integer> OPT_VSMARTCARD_PORT = parser.accepts("vsmartcard-port", "VSmartCard port").withRequiredArg().ofType(Integer.class).defaultsTo(VSmartCard.DEFAULT_VSMARTCARD_PORT);
    static OptionSpec<String> OPT_VSMARTCARD_HOST = parser.accepts("vsmartcard-host", "VSmartCard host").withRequiredArg().ofType(String.class).defaultsTo(VSmartCard.DEFAULT_VSMARTCARD_HOST);

    // Oracle options
    static OptionSpec<Void> OPT_JCSDK = parser.accepts("jcsdk", "Run a JCSDK server");
    static OptionSpec<Integer> OPT_JCSDK_PORT = parser.accepts("jcsdk-port", "port to listen on").withRequiredArg().ofType(Integer.class).defaultsTo(JCSDKServer.DEFAULT_JCSDK_PORT);
    static OptionSpec<String> OPT_JCSDK_HOST = parser.accepts("jcsdk-host", "host to listen on").withRequiredArg().ofType(String.class).defaultsTo(JCSDKServer.DEFAULT_JCSDK_HOST);

    // ATR to report
    static OptionSpec<String> OPT_ATR = parser.accepts("atr", "ATR to use (hex)").withRequiredArg().ofType(String.class);

    // .cap/.jar files to load
    static OptionSpec<File> toLoad = parser.nonOptions("path to .cap or .jar or classes directory").ofType(File.class);

    static OptionSpec<String> OPT_APPLET = parser.accepts("applet", "Applet to install").withRequiredArg().ofType(String.class);
    static OptionSpec<String> OPT_PARAMS = parser.accepts("params", "Installation parameters").withRequiredArg().ofType(String.class);
    static OptionSpec<String> OPT_AID = parser.accepts("aid", "Applet AID").withRequiredArg().ofType(String.class);

    // While Simulator interface has an ATR interface, we don't really handle it on that level
    // The only relation would be GPSystem.setATRHistBytes(). So for now the ATR can be set freely
    // for adapters.
    static final byte[] DEFAULT_ATR = Hex.decode("3B9F968131FE454F52434C2D4A43332E324750322E3323");

    // Class loader
    static final AppletClassLoader loader = new AppletClassLoader();

    public static void main(String[] args) {
        String version = JCardSimTool.class.getPackage().getImplementationVersion();

        try {
            OptionSet options = parser.parse(args);

            if (options.has(OPT_HELP) || args.length == 0) {
                parser.printHelpOn(System.out);
                return;
            }

            if (options.nonOptionArguments().isEmpty()) {
                System.err.println("Missing applets");
                parser.printHelpOn(System.err);
                System.exit(2);
            }

            Set<String> availableApplets = new TreeSet<>();
            Map<String, byte[]> defaultAID = new HashMap<>();
            // Load non-options
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
                    System.out.println("- " + applet);
                }
                System.exit(1);
            }

            // Set ATR.
            final byte[] atr = options.has(OPT_ATR) ? Hex.decode(options.valueOf(OPT_ATR)) : DEFAULT_ATR;

            // Set up simulator. Right now a sample thingy
            CardInterface sim = new ThreadedSimulator(spec);
            byte[] aid_bytes = Hex.decode("010203040506");
            ExecutorService exec = Executors.newFixedThreadPool(3);

            List<RemoteTerminalProtocol> adapters = new ArrayList<>();

            if (options.has(OPT_VSMARTCARD) || options.has(OPT_VSMARTCARD_PORT) || options.has(OPT_VSMARTCARD_HOST)) {
                int port = options.valueOf(OPT_VSMARTCARD_PORT);
                String host = options.has(OPT_VSMARTCARD_HOST) ? options.valueOf(OPT_VSMARTCARD_HOST) : VSmartCard.DEFAULT_VSMARTCARD_HOST;
                System.out.printf("vsmartcard to host %s port %d%n", host, port);
                RemoteTerminalProtocol adapter = new VSmartCard(host, port, sim);
                adapter.setATR(atr);
                adapters.add(adapter);
            }

            if (options.has(OPT_JCSDK) || options.has(OPT_JCSDK_PORT) || options.has(OPT_JCSDK_HOST)) {
                int port = options.hasArgument(OPT_JCSDK_PORT) ? options.valueOf(OPT_JCSDK_PORT) : JCSDKServer.DEFAULT_JCSDK_PORT;
                String host = options.has(OPT_JCSDK_HOST) ? options.valueOf(OPT_JCSDK_HOST) : JCSDKServer.DEFAULT_JCSDK_HOST;
                System.out.printf("jcsdk on host %s port %d%n", host, port);
                RemoteTerminalProtocol adapter = new JCSDKServer(host, port, sim);
                adapter.setATR(atr);
                adapters.add(adapter);
            }

            // Trap ctrl-c and similar signals
            Thread shutdownThread = new Thread(() -> {
                System.err.println("Quitting jcardsim");
                exec.shutdownNow();
            });

            if (adapters.isEmpty()) {
                System.err.println("Use one of --vsmartcard or --jcsdk");
                System.exit(2);
            }

            Runtime.getRuntime().addShutdownHook(shutdownThread);
            // This blocks until all are done, unless ctrl-c is hit
            exec.invokeAll(adapters);
            Runtime.getRuntime().removeShutdownHook(shutdownThread);
            exec.shutdownNow();
            while (!exec.isTerminated()) {
                if (exec.awaitTermination(1, TimeUnit.MINUTES))
                    break;
            }
            System.out.println("Thank you for using jcardsim " + version + "!");
        } catch (OptionException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
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