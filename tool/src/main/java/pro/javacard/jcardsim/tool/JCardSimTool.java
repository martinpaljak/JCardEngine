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

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.samples.HelloWorldApplet;
import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.SystemException;
import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class JCardSimTool {
    private static final Logger log = LoggerFactory.getLogger(JCardSimTool.class);

    // Default values
    public static final int DEFAULT_VSMARTCARD_PORT = 8099;
    public static final int DEFAULT_BIXVREADER_PORT = 21238;
    public static final int DEFAULT_JCSDK_PORT = 9025;
    public static final byte[] DEFAULT_ATR = Hex.decode("3B9F968131FE454F52434C2D4A43332E324750322E3323");

    public static void main(String[] args) {

        String me = JCardSimTool.class.getProtectionDomain()
                .getCodeSource()
                .getLocation()
                .getPath();

        String version = JCardSimTool.class.getPackage().getImplementationVersion();

        System.out.printf("%s v%s%n", me, version);

        OptionParser parser = new OptionParser();

        // Main options
        OptionSpec<Void> OPT_HELP = parser.acceptsAll(Arrays.asList("h", "help"), "Show this help").forHelp();

        // VSmartCard options
        OptionSpec<Integer> OPT_VSMARTCARD = parser.accepts("vsmartcard", "Run a VSmartCard server").withOptionalArg().ofType(Integer.class).defaultsTo(DEFAULT_VSMARTCARD_PORT);

        // Oracle options
        OptionSpec<Integer> OPT_JCSDK = parser.accepts("jcsdk", "Run a JavaCard SDK simulator-compatible server").withOptionalArg().ofType(Integer.class).defaultsTo(DEFAULT_JCSDK_PORT);

        OptionSpec<String> OPT_HOST = parser.accepts("host", "host to connect to or bind to").withRequiredArg().ofType(String.class);

        OptionSpec<String> OPT_ATR = parser.accepts("atr", "ATR to send (hex)").withRequiredArg().ofType(String.class);

        try {
            OptionSet options = parser.parse(args);

            if (options.has(OPT_HELP) || args.length == 0) {
                parser.printHelpOn(System.out);
                return;
            }

            // Set up simulator. Right now a sample thingy
            byte[] aid_bytes = Hex.decode("010203040506");
            Simulator sim = new Simulator();
            sim.installApplet(new AID(aid_bytes, (short) 0, (byte) aid_bytes.length), HelloWorldApplet.class);

            ExecutorService exec = Executors.newFixedThreadPool(3);


            List<RemoteTerminalProtocol> adapters = new ArrayList<>();

            if (options.has(OPT_VSMARTCARD)) {
                int port = options.valueOf(OPT_VSMARTCARD);
                String host = options.has(OPT_HOST) ? options.valueOf(OPT_HOST) : "127.0.0.1";
                System.out.printf("vsmartcard on port %d%n", port);
                adapters.add(new VSmartCard(host, port, sim));
            }

            if (options.has(OPT_JCSDK)) {
                int port = options.hasArgument(OPT_JCSDK) ? options.valueOf(OPT_JCSDK) : DEFAULT_JCSDK_PORT;
                String host = options.has(OPT_HOST) ? options.valueOf(OPT_HOST) : "0.0.0.0";
                System.out.printf("jcsdk on port %d%n", port);
                adapters.add(new JCSDKServer(port, sim));
            }


            // Trap ctrl-c and similar signals
            Thread shutdownThread = new Thread(() -> {
                System.err.println("Quitting jcardsim");
                exec.shutdown();
            });

            for (RemoteTerminalProtocol proto : adapters) {
                exec.submit(proto);
            }
            Runtime.getRuntime().addShutdownHook(shutdownThread);
            while (!exec.isTerminated()) {
                if (exec.awaitTermination(1, TimeUnit.MINUTES))
                    break;
            }
            System.out.println("jcardsim is done.");
        } catch (OptionException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(2);
        }
    }


    @SuppressWarnings("unchecked")
    private Class<? extends Applet> requireExtendsApplet(Class<?> cls) {
        if (!Applet.class.isAssignableFrom(cls)) {
            throw new SystemException(SystemException.ILLEGAL_VALUE);
        }
        return (Class<? extends Applet>) cls;
    }

    static class AppletClassLoader extends URLClassLoader {

        AppletClassLoader() {
            super(new URL[0], Simulator.class.getClassLoader());
        }

        void addApplet(byte[] contents) throws IOException {
            Path tmp = Files.createTempFile("applet", ".jar");
            Files.write(tmp, contents);
            addURL(tmp.toUri().toURL());
        }

        void addApplet(Path file) throws IOException {
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
                }
            }

            addURL(tmp.toUri().toURL());
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