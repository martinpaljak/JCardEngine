// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine;

import apdu4j.core.BIBO;
import apdu4j.pcsc.sim.SynthesizedCardTerminal;
import apdu4j.pcsc.sim.SynthesizedCardTerminals;
import apdu4j.prefs.Preference;
import apdu4j.prefs.PreferenceProvider;
import apdu4j.prefs.Preferences;
import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import javacard.framework.Applet;
import pro.javacard.engine.faulty.FaultyConfig;
import pro.javacard.engine.globalplatform.GlobalPlatformEngine;
import pro.javacard.engine.globalplatform.SCPConfig;

import javax.smartcardio.TerminalFactory;
import java.time.Duration;
import java.util.regex.Pattern;

// External programmer-facing interface: install/delete applets and open APDU (BIBO) sessions.
public interface JavaCardEngine {
    // Optional deterministic RNG seed. Absent (Parameter, not Default) means a real random card;
    // a value seeds every card RNG for reproducible key generation and signatures. GH #20.
    Preference.Parameter<Long> RNG_SEED = Preference.parameter("jcardengine.rng.seed", Long.class, false);

    // Regex searched in each traced comment line; only matching lines are logged, unset is silent.
    Preference.Parameter<String> TRACE_FILTER = Preference.parameter("jcardengine.trace.filter", String.class, false);

    AID installApplet(AID aid, Class<? extends Applet> appletClass, byte[] parameters);

    default AID installApplet(AID aid, Class<? extends Applet> appletClass) {
        return installApplet(aid, appletClass, new byte[0]);
    }

    AID installExposedApplet(AID aid, Class<? extends Applet> appletClass, byte[] parameters);

    default AID installExposedApplet(AID aid, Class<? extends Applet> appletClass) {
        return installExposedApplet(aid, appletClass, new byte[0]);
    }

    void deleteApplet(AID aid);

    void loadApplet(AID packageAid, AID appletAid, Class<? extends Applet> appletClass);

    Applet getApplet(AID aid);

    byte[] getATR();

    // Connect with default settings (no timeout, any protocol, no reset on close)
    default BIBO connect() {
        return connectFor(Duration.ZERO, "*", false);
    }

    default BIBO connect(String protocol) {
        return connectFor(Duration.ZERO, protocol, false);
    }

    default BIBO connect(String protocol, boolean resetOnClose) {
        return connectFor(Duration.ZERO, protocol, resetOnClose);
    }

    BIBO connectFor(Duration duration, String protocol, boolean resetOnClose);

    // pcsc-sim integration: factory mode backed by this engine
    default SynthesizedCardTerminal toTerminal() {
        return toTerminal("jcardengine.Terminal");
    }

    default SynthesizedCardTerminal toTerminal(String name) {
        return toTerminal(name, "T=1");
    }

    // A reader is either contact or contactless, so the card behind it answers on that interface
    // alone. Reaching a dual-interface card both ways takes a terminal for each.
    default SynthesizedCardTerminal toTerminal(String name, String protocol) {
        var terminal = new SynthesizedCardTerminal(name, protocol);
        // Factory mode: engine persists, fresh BIBO per connect, reset on close
        terminal.presentFactory(p -> connect(p, true), getATR());
        return terminal;
    }

    default TerminalFactory toTerminalFactory() {
        var terminals = new SynthesizedCardTerminals();
        terminals.addTerminal(toTerminal());
        return terminals.toFactory();
    }

    static JavaCardEngine create() {
        return new Builder().build();
    }

    final class Builder {
        private ClassLoader classLoader = getClass().getClassLoader();
        private FaultyConfig faultConfig;
        private SCPConfig scpConfig = SCPConfig.defaultConfig();
        private Preferences preferences = Preferences.from(PreferenceProvider.systemProperties());

        public Builder withClassLoader(ClassLoader cl) {
            this.classLoader = cl;
            return this;
        }

        public Builder preferences(Preferences prefs) {
            this.preferences = prefs;
            return this;
        }

        public Builder faulty(FaultyConfig config) {
            this.faultConfig = config;
            return this;
        }

        public Builder withSCP(SCPConfig config) {
            this.scpConfig = config;
            return this;
        }

        public JavaCardEngine build() {
            var gp = new GlobalPlatformEngine(scpConfig);
            Long seed = preferences.valueOf(RNG_SEED).orElse(null);
            Pattern trace = preferences.valueOf(TRACE_FILTER).map(Pattern::compile).orElse(null);
            var sim = new Simulator(classLoader, faultConfig, gp, seed, trace);
            var scope = sim.asCurrent();
            try (scope) {
                // Constructors use JCSystem so we need the "current" reference
                gp.bootstrap();
            }
            // Power on the freshly bootstrapped card: a reset-on-close session arms the power-up
            // that selects the default applet on the first command.
            sim.connect("*", true).close();
            return sim;
        }
    }
}
