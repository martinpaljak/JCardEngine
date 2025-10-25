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
package pro.javacard.engine.globalplatform;

import javacard.framework.AID;
import javacard.framework.Applet;
import org.globalplatform.CVM;
import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.engine.JavaCardEngineException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GlobalPlatform {
    private static final Logger log = LoggerFactory.getLogger(GlobalPlatform.class);
    // TODO: programmatic flag
    private final SecureChannel sc = System.getProperty("pro.javacard.engine.scp02", "false").equals("true") ? new SCP02SecureChannelImpl() : new SCP03SecureChannelImpl();
    private final GlobalPINImpl gpin = new GlobalPINImpl();

    private byte card_state = GPSystem.CARD_SECURED;

    record GPPackage(String pkg, AID aid) {
    }

    record GPApplet(AID aid, Class<? extends Applet> appletClass) {
    }

    private Map<GPPackage, List<GPApplet>> packages = new HashMap<>();

    public void loadClass(AID packageAid, AID appletAid, Class<? extends Applet> appletClass) {
        String pkgname = appletClass.getPackageName();
        GPPackage pkg = null;
        // Locate any existing package
        for (var p : packages.keySet()) {
            if (p.pkg().equals(pkgname) || p.aid().equals(packageAid)) {
                log.debug("Matching entry: {}", p);
                pkg = p;
                break;
            }
        }
        if (pkg == null) {
            pkg = new GPPackage(pkgname, packageAid);
            packages.put(pkg, new ArrayList<>());
        }

        var applets = packages.get(pkg);

        // Check for same AID
        for (var a : applets) {
            if (a.aid().equals(appletAid)) {
                log.error("Applet already present");
                throw new JavaCardEngineException("Applet already loaded");
            }
        }

        applets.add(new GPApplet(appletAid, appletClass));
        log.info("Loaded applet {}", appletClass.getCanonicalName());
    }

    public Class<? extends Applet> locateApplet(AID packageAid, AID appletAid) {
        for (var e : packages.entrySet()) {
            if (e.getKey().aid().equals(packageAid)) {
                log.debug("Matched package {} by {}", e.getKey().pkg(), e.getKey().aid());
                for (var app : e.getValue()) {
                    if (app.aid().equals(appletAid)) {
                        log.debug("Found applet {} in pkg {}", appletAid, e.getKey().pkg());
                        return app.appletClass();
                    }
                }
            }
        }
        log.warn("pkg {} / applet {} not found in registry.", packageAid, appletAid);
        return null;
    }

    public SecureChannel getSecureChannel() {
        return sc;
    }

    public void reset() {
        sc.resetSecurity();
    }

    public CVM getGlobalPIN() {
        return gpin;
    }

    public byte getCardState() {
        return card_state;
    }

    public boolean lockCard() {
        // The OPEN shall check that the Application invoking this method has the Card Lock Privilege. If not, the transition shall be rejected.
        card_state = GPSystem.CARD_LOCKED;
        return false;
    }

    public boolean terminateCard() {
        // The OPEN shall check that the Application invoking this method has the Card Terminate Privilege. If not, the transition shall be rejected.
        card_state = GPSystem.CARD_TERMINATED;
        return false;
    }
}
