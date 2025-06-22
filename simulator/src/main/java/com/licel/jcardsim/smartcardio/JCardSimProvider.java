/*
 * Copyright 2012 Licel LLC.
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
package com.licel.jcardsim.smartcardio;

import java.security.Provider;

/**
 * Provider object for the Java Card Terminal emulating.
 *
 * @author LICEL LLC
 * <p>
 * You can configure this by following system properties:
 * <p>
 * Card ATR:
 * com.licel.jcardsim.smartcardio.ATR
 */
public final class JCardSimProvider extends Provider {

    public JCardSimProvider() {
        super("jCardSim", "1.0", "jCardSim Virtual Terminal Provider");
        put("TerminalFactory.jCardSim", JCSFactory.class.getName());
    }
}
