/*
 * Copyright 2011 Licel LLC.
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

import javacard.framework.*;

/**
 * Base implementation of <code>JCSystem</code>.
 *
 * @see JCSystem
 */
public class SimulatorSystem {
    /**
     * Response status : Applet creation failed = 0x6444
     */
    public static final short SW_APPLET_CREATION_FAILED = 0x6444;

    /**
     * Response status : Exception occurred = 0x6424
     */
    public static final short SW_EXCEPTION_OCCURRED = 0x6424;

    /**
     * Holds the currently active instance
     */
    private static final ThreadLocal<SimulatorRuntime> currentRuntime = new ThreadLocal<>();

    /**
     * the default instance. Used by <code>Simulator</code>
     */
    public static final SimulatorRuntime DEFAULT_RUNTIME;

    static {
        // XXX: the threadLocal currentRuntime does not seem to make much sense
        // As communication is sequential by design, would like to have two independent
        // simulators inside one thread (think: simulating interaction between two cards)
        // See also: https://github.com/licel/jcardsim/issues/208
        DEFAULT_RUNTIME = setCurrentInstance(new SimulatorRuntime());
    }

    /**
     * Get the currently active SimulatorRuntime instance
     * <p>
     * This method should be only called by JCE implementation classes like
     * <code>JCSystem</code>
     *
     * @return current instance
     */
    public static SimulatorRuntime instance() {
        SimulatorRuntime simulatorRuntime = currentRuntime.get();
        if (simulatorRuntime == null) {
            throw new AssertionError("No current simulator instance");
        }
        return simulatorRuntime;
    }

    /**
     * Internal method to set the currently active SimulatorRuntime
     *
     * @param simulatorRuntime simulatorRuntime to set
     * @return <code>simulatorRuntime</code>
     */
    static SimulatorRuntime setCurrentInstance(SimulatorRuntime simulatorRuntime) {
        currentRuntime.set(simulatorRuntime);
        return simulatorRuntime;
    }
}
