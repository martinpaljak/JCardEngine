/*
 * Copyright 2025 Martin Paljak
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
package com.licel.jcardsim.base;

import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Applet;

/**
 * Represents an Applet instance we keep in the virtual "registry"
 */
public class ApplicationInstance {
    // TODO: track privileges of install
    private final AID aid;
    private final Object instance;
    private final boolean exposed;

    public ApplicationInstance(AID aid, Object instance, boolean exposed) {
        this.aid = aid;
        this.instance = instance;
        this.exposed = exposed;
    }

    public Applet getApplet() {
        if (exposed) {
            return (Applet) instance;
        }
        // If the class was instantiated in the isolator classloader
        // class identity would differ. So this proxy helps with "instanceof" etc.
        try {
            return ReflectiveClassProxy.proxy(instance, Applet.class);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // FIXME: this is part of the registry as the key.
    public AID getAID() {
        return aid;
    }

    @Override
    public String toString() {
        return String.format("ApplicationInstance (%s)", AIDUtil.toString(aid));
    }
}
