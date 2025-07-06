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
import pro.javacard.engine.EngineSession;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.engine.adapters.AbstractTCPAdapter;
import pro.javacard.engine.adapters.JCSDKClient;
import pro.javacard.engine.adapters.JCSDKServer;
import pro.javacard.engine.adapters.VSmartCardClient;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

public class JCardTool {
    static OptionParser parser = new OptionParser();

    // Generic options
    static OptionSpec<Void> OPT_HELP = parser.acceptsAll(Arrays.asList("h", "help"), "Show this help").forHelp();
    static OptionSpec<Void> OPT_VERSION = parser.acceptsAll(Arrays.asList("V", "version"), "Show version");
    static OptionSpec<Void> OPT_CONTROL = parser.acceptsAll(Arrays.asList("c", "control"), "Start control interface");

    // VSmartCard options
    static OptionSpec<Void> OPT_VSMARTCARD = parser.accepts("vsmartcard", "Run a VSmartCard client");
    static OptionSpec<Integer> OPT_VSMARTCARD_PORT = parser.accepts("vsmartcard-port", "VSmartCard port").withRequiredArg().ofType(Integer.class).defaultsTo(VSmartCardClient.DEFAULT_VSMARTCARD_PORT);
    static OptionSpec<String> OPT_VSMARTCARD_HOST = parser.accepts("vsmartcard-host", "VSmartCard host").withRequiredArg().ofType(String.class).defaultsTo(VSmartCardClient.DEFAULT_VSMARTCARD_HOST);
    static OptionSpec<String> OPT_VSMARTCARD_ATR = parser.accepts("vsmartcard-atr", "VSmartCard ATR").withRequiredArg().ofType(String.class).defaultsTo(AbstractTCPAdapter.DEFAULT_ATR_HEX);
    static OptionSpec<String> OPT_VSMARTCARD_PROTOCOL = parser.accepts("vsmartcard-protocol", "VSmartCard protocol").withRequiredArg().ofType(String.class).defaultsTo("*");

    // Oracle options
    static OptionSpec<Void> OPT_JCSDK = parser.accepts("jcsdk", "Run a JCSDK server");
    static OptionSpec<Integer> OPT_JCSDK_PORT = parser.accepts("jcsdk-port", "JCSDK port").withRequiredArg().ofType(Integer.class).defaultsTo(JCSDKServer.DEFAULT_JCSDK_PORT);
    static OptionSpec<String> OPT_JCSDK_HOST = parser.accepts("jcsdk-host", "JCSDK host").withRequiredArg().ofType(String.class).defaultsTo(JCSDKServer.DEFAULT_JCSDK_HOST);
    static OptionSpec<String> OPT_JCSDK_ATR = parser.accepts("jcsdk-atr", "JCSDK ATR").withRequiredArg().ofType(String.class).defaultsTo(AbstractTCPAdapter.DEFAULT_ATR_HEX);
    static OptionSpec<String> OPT_JCSDK_PROTOCOL = parser.accepts("jcsdk-protocol", "JCSDK protocol").withRequiredArg().ofType(String.class).defaultsTo("*");

    // Passthrough
    static OptionSpec<String> OPT_PASSTHROUGH_HOST = parser.accepts("passthrough-host", "JCSDK simulator host").withRequiredArg().ofType(String.class);

    // Generic override.
    static OptionSpec<String> OPT_ATR = parser.accepts("atr", "ATR to use (hex)").withRequiredArg().ofType(String.class).defaultsTo(AbstractTCPAdapter.DEFAULT_ATR_HEX);
    static OptionSpec<String> OPT_PROTOCOL = parser.accepts("protocol", "Protocol to use").withRequiredArg().ofType(String.class).defaultsTo("T=1");

    // .cap/.jar files to load
    static OptionSpec<File> toLoad = parser.nonOptions("path to .cap or .jar or classes directory").ofType(File.class);

    static OptionSpec<String> OPT_APPLET = parser.accepts("applet", "Applet class to install").withRequiredArg().ofType(String.class);
    static OptionSpec<String> OPT_PARAMS = parser.accepts("params", "Installation parameters").withRequiredArg().ofType(String.class);
    static OptionSpec<String> OPT_AID = parser.accepts("aid", "Applet AID").withRequiredArg().ofType(String.class);

    // Class loader for .jar/.cap/classes
    static final AppletClassLoader loader = new AppletClassLoader();


    static AbstractTCPAdapter configureVSmartCard(AbstractTCPAdapter adapter, OptionSet options) {
        adapter = adapter.withHost(options.valueOf(OPT_VSMARTCARD_HOST));
        adapter = adapter.withPort(options.valueOf(OPT_VSMARTCARD_PORT));
        if (options.has(OPT_ATR)) {
            adapter = adapter.withATR(Hex.decode(options.valueOf(OPT_ATR)));
        }
        if (options.has(OPT_VSMARTCARD_ATR)) {
            adapter = adapter.withATR(Hex.decode(options.valueOf(OPT_VSMARTCARD_ATR)));
        }
        return adapter;
    }

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

            if (options.nonOptionArguments().isEmpty() && !options.has(OPT_PASSTHROUGH_HOST)) {
                System.err.println("Missing applets. Check --help");
                System.exit(2);
            }


            ExecutorService exec = Executors.newFixedThreadPool(3);
            List<AbstractTCPAdapter> adapters = new ArrayList<>();

            if (options.has(OPT_PASSTHROUGH_HOST)) {
                JCSDKClient upstream = new JCSDKClient(options.valueOf(OPT_PASSTHROUGH_HOST), options.valueOf(OPT_JCSDK_PORT));
                AbstractTCPAdapter adapter = new VSmartCardClient(upstream);
                adapter = configureVSmartCard(adapter, options);
                adapters.add(adapter);
            } else {
                Set<String> availableApplets = new TreeSet<>();
                Map<String, byte[]> defaultAID = new HashMap<>();

                // Set up simulator. Right now a sample thingy
                JavaCardEngine sim = JavaCardEngine.create().withClassLoader(loader);

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

                for (InstallSpec s : spec) {
                    sim.installApplet(s.getAID(), s.getAppletClass(), s.getParamters());
                }

                if (options.has(OPT_VSMARTCARD) || options.has(OPT_VSMARTCARD_PORT) || options.has(OPT_VSMARTCARD_HOST) || options.has(OPT_VSMARTCARD_PROTOCOL) || options.has(OPT_VSMARTCARD_ATR)) {
                    String protocol = options.has(OPT_VSMARTCARD_PROTOCOL) ? options.valueOf(OPT_VSMARTCARD_PROTOCOL) : options.valueOf(OPT_PROTOCOL);
                    AbstractTCPAdapter adapter = new VSmartCardClient(() -> sim.connectFor(Duration.ofSeconds(1), protocol)); // TODO: parameter for timeout
                    adapter = configureVSmartCard(adapter, options);
                    adapters.add(adapter);
                }

                if (options.has(OPT_JCSDK) || options.has(OPT_JCSDK_PORT) || options.has(OPT_JCSDK_HOST) || options.has(OPT_JCSDK_PROTOCOL) || options.has(OPT_JCSDK_ATR)) {
                    String protocol = options.has(OPT_JCSDK_PROTOCOL) ? options.valueOf(OPT_JCSDK_PROTOCOL) : options.valueOf(OPT_PROTOCOL);
                    AbstractTCPAdapter adapter = new JCSDKServer(() -> sim.connect(protocol));
                    adapter = adapter.withHost(options.valueOf(OPT_JCSDK_HOST));
                    adapter = adapter.withPort(options.valueOf(OPT_JCSDK_PORT));
                    if (options.has(OPT_ATR)) {
                        adapter = adapter.withATR(Hex.decode(options.valueOf(OPT_ATR)));
                    }
                    if (options.has(OPT_JCSDK_ATR)) {
                        adapter = adapter.withATR(Hex.decode(options.valueOf(OPT_JCSDK_ATR)));
                    }
                    adapters.add(adapter);
                }
            }

            // Trap ctrl-c and similar signals
            Thread shutdownThread = new Thread(() -> {
                System.err.println("Ctrl-C, quitting JCardEngine");
                exec.shutdownNow();
            });

            if (adapters.isEmpty()) {
                System.err.println("Use one of --vsmartcard or --jcsdk or --passthrough-host");
                System.exit(2);
            }

            Runtime.getRuntime().addShutdownHook(shutdownThread);
            if (options.has(OPT_CONTROL)) {
                adapters.forEach(exec::submit);
                boolean connected = true;
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
                            // 't' tap/reset
                            System.err.println("Triggering a fresh tap: boop!");
                            adapters.forEach(AbstractTCPAdapter::tap);
                        } else if (c == 99) {
                            // 'c' for connection state
                            connected = !connected;
                            boolean finalConnected = connected;
                            System.err.println(String.format("%s the card", connected ? "Connecting" : "Disconnecting"));
                            adapters.forEach(a -> a.connected(finalConnected));
                        } else {
                            // print help
                            //System.err.println("Unknown key: " + c);
                            System.err.println("Press 't' to trigger tap, 'c' to toggle connection, 'q' or Esc to quit.");
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
        } catch (IllegalArgumentException e) {
            System.err.println(e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            System.err.println(e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(2);
        }
    }

    @SuppressWarnings("unchecked")
    private static Class<? extends Applet> requireExtendsApplet(Class<?> cls) {
        System.out.println("Validating " + cls.getName());
        if (!Applet.class.isAssignableFrom(cls)) {
            throw new SystemException(SystemException.ILLEGAL_VALUE);
        }
        return (Class<? extends Applet>) cls;
    }
}