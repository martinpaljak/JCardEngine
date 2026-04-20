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
package pro.javacard.engine;

import apdu4j.pcsc.sim.SynthesizedCardTerminal;
import apdu4j.pcsc.sim.SynthesizedCardTerminals;
import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import javacard.framework.Applet;
import pro.javacard.engine.faulty.FaultyConfig;
import pro.javacard.engine.globalplatform.GlobalPlatform;
import pro.javacard.engine.globalplatform.GlobalPlatformApplet;
import pro.javacard.engine.globalplatform.SCPConfig;

import javax.smartcardio.TerminalFactory;
import java.time.Duration;

// External, programmer-facing interface. Manages the "secure element" by installing and deleting
// applets, and opening APDU transports (BIBO sessions) to it.
public interface JavaCardEngine {
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

    void reset();

    byte[] getATR();

    // Connect with default settings (no timeout, any protocol, no reset on close)
    default EngineSession connect() {
        return connectFor(Duration.ZERO, "*", false);
    }

    default EngineSession connect(String protocol) {
        return connectFor(Duration.ZERO, protocol, false);
    }

    EngineSession connectFor(Duration duration, String protocol, boolean resetOnClose);

    // pcsc-sim integration: factory mode backed by this engine
    default SynthesizedCardTerminal toTerminal() {
        return toTerminal("jcardengine.Terminal");
    }

    default SynthesizedCardTerminal toTerminal(String name) {
        var terminal = new SynthesizedCardTerminal(name, "T=1");
        // Factory mode: engine persists, fresh BIBO per connect, reset on close
        terminal.presentFactory(protocol -> connectFor(Duration.ZERO, protocol, true), getATR());
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
        private SCPConfig scpConfig;

        public Builder withClassLoader(ClassLoader cl) {
            this.classLoader = cl;
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
            var gp = new GlobalPlatform(scpConfig);
            var sim = new Simulator(classLoader, faultConfig, gp);
            sim.installExposedApplet(GlobalPlatformApplet.OPEN_AID, GlobalPlatformApplet.class);
            return sim;
        }
    }
}
