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

import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import javacard.framework.Applet;

import java.time.Duration;

// This is the external, programmer-facing interface. It allows to manage the "secure element" by installing and deleting
// applets, and to open APDU-transports to it.
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

    Applet getApplet(AID aid);

    void reset();

    default EngineSession connect() {
        return connectFor(Duration.ZERO, "*");
    }

    default EngineSession connect(String protocol) {
        return connectFor(Duration.ZERO, protocol);
    }

    EngineSession connectFor(Duration duration, String protocol);

    JavaCardEngine exposed(boolean flag);

    JavaCardEngine withClassLoader(ClassLoader parent);

    static JavaCardEngine create() {
        return new Simulator();
    }
}
