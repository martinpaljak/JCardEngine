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

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import java.util.ArrayList;
import java.util.List;

/**
 * CardTerminals implementation class.
 *
 * @author LICEL LLC
 */
public class JCSCardTerminals extends CardTerminals {

    /**
     * Returns only one terminal with state ALL|CARD_PRESENT|CARD_INSERTION,
     * in other case returns empty list.
     */
    // XXX: just a single terminal is exposed, with uncontrolled simulator setup. Consider removal or merging with CardTerminalSimulator
    public List<CardTerminal> list(State state) throws CardException {
        List<CardTerminal> terminals = new ArrayList<>();
        switch (state) {
            case ALL:
            case CARD_PRESENT:
            case CARD_INSERTION:
                terminals.add(new JCSTerminal());
                return terminals;
            default:
                // No reader without a card, ever.
                return terminals;
        }
    }

    /**
     * Immediately returns true
     */
    public boolean waitForChange(long l) throws CardException {
        return true;
    }
}
