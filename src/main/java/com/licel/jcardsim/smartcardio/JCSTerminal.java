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

import com.licel.jcardsim.base.Simulator;

import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;

/**
 * CardTerminal implementation class.
 *
 * @author LICEL LLC
 */
public class JCSTerminal extends CardTerminal {

    final static String NAME = "jCardSim.Terminal";
    static Simulator simulator = null;

    public JCSTerminal() {
        simulator = new Simulator();
    }

    public String getName() {
        return NAME;
    }

    /**
     * @see javax.smartcardio.CardTerminal#connect(String)
     * @see com.licel.jcardsim.base.Simulator#changeProtocol(String)
     */
    public Card connect(String protocol) throws CardException {
        if (protocol == null) {
            throw new NullPointerException("protocol");
        } else if (protocol.equals("*")) {
            simulator.changeProtocol("T=0");
        } else {
            simulator.changeProtocol(protocol);
        }

        return new JCSCard(simulator);
    }

    /**
     * Always returns true
     */
    public boolean isCardPresent() throws CardException {
        return true;
    }

    /**
     * Immediately returns true
     */
    public boolean waitForCardPresent(long l) throws CardException {
        return true;
    }

    /**
     * Immediately returns true
     */
    public boolean waitForCardAbsent(long l) throws CardException {
        return false;
    }
}
