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

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBO;
import apdu4j.core.BIBOException;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Wrapper for apdu4j
public class SimulatorBIBO implements BIBO {
    private static final Logger log = LoggerFactory.getLogger(SimulatorBIBO.class);
    final EngineSession sim;

    public SimulatorBIBO(EngineSession sim) {
        this.sim = sim;
    }

    @Override
    public byte[] transceive(byte[] bytes) throws BIBOException {
        log.info(">> " + Hex.toHexString(bytes));
        byte[] response = sim.transmitCommand(bytes);
        log.info("<< " + Hex.toHexString(response));
        return response;
    }

    @Override
    public void close() {
        sim.close();
    }

    public static APDUBIBO wrap(EngineSession s) {
        return new APDUBIBO(new SimulatorBIBO(s));
    }
}
