// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine;

import apdu4j.pcsc.sim.SynthesizedCardTerminal;
import apdu4j.pcsc.sim.SynthesizedCardTerminals;
import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import javacard.framework.Applet;
import pro.javacard.engine.faulty.FaultyConfig;
import pro.javacard.engine.globalplatform.EngineRegistryEntry;
import pro.javacard.engine.globalplatform.GlobalPlatform;
import pro.javacard.engine.globalplatform.KeySet;
import pro.javacard.engine.globalplatform.SCPConfig;
import pro.javacard.engine.globalplatform.SecurityDomainApplet;

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

    default EngineSession connect(String protocol, boolean resetOnClose) {
        return connectFor(Duration.ZERO, protocol, resetOnClose);
    }

    EngineSession connectFor(Duration duration, String protocol, boolean resetOnClose);

    // pcsc-sim integration: factory mode backed by this engine
    default SynthesizedCardTerminal toTerminal() {
        return toTerminal("jcardengine.Terminal");
    }

    default SynthesizedCardTerminal toTerminal(String name) {
        var terminal = new SynthesizedCardTerminal(name, "T=1");
        // Factory mode: engine persists, fresh BIBO per connect, reset on close
        terminal.presentFactory(protocol -> connect(protocol, true), getATR());
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
            var resolvedScp = scpConfig != null ? scpConfig : new SCPConfig.SCP03(true);
            var gp = new GlobalPlatform(resolvedScp);
            var sim = new Simulator(classLoader, faultConfig, gp);
            // Plant the ISD entry directly: the OPEN is an override, not a normal install.
            // Structural plant of the factory KVN (0xFF) keyset matching the SCP type;
            // bypasses the personalization-only factory trigger that putKey applies.
            var openSda = new SecurityDomainApplet();
            var openEntry = EngineRegistryEntry.forISD(SecurityDomainApplet.OPEN_AID, openSda, true,
                    SecurityDomainApplet.ISD_DEFAULT_PRIVILEGES, SecurityDomainApplet.SSD_PACKAGE_AID);
            KeySet bootstrap;
            if (resolvedScp instanceof SCPConfig.SCP02 c) {
                bootstrap = KeySet.ofMaster((byte) 0xFF, KeySet.TYPE_DES3, c.masterKey());
            } else if (resolvedScp instanceof SCPConfig.SCP03 c) {
                bootstrap = KeySet.ofMaster((byte) 0xFF, KeySet.TYPE_AES, c.masterKey());
            } else {
                throw new IllegalArgumentException("Unsupported SCP config: " + resolvedScp);
            }
            openSda.seedKey(bootstrap);
            sim.getRegistry().put(SecurityDomainApplet.OPEN_AID, openEntry);
            gp.addBuiltinPackage(SecurityDomainApplet.SSD_PACKAGE_AID, SecurityDomainApplet.SSD_MODULE_AID, SecurityDomainApplet.class);
            sim.reset();
            return sim;
        }
    }
}
