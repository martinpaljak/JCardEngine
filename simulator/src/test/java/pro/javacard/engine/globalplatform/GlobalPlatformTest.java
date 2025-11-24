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
package pro.javacard.engine.globalplatform;

import apdu4j.core.*;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.EngineSession;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.gp.GPCrypto;
import pro.javacard.gp.GPRegistryEntry;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.keys.PlaintextKeys;

import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class GlobalPlatformTest {

    @Test
    public void testSecureChannel() throws Exception {
        JavaCardEngine sim = JavaCardEngine.create();
        AID appletAID = AIDUtil.create("010203040506070809");
        sim.installApplet(appletAID, GlobalPlatformTestApplet.class); // coverage!

        PlaintextKeys pk = PlaintextKeys.defaultKey();
        try (EngineSession instance = sim.connect()) {
            APDUBIBO bibo = SimulatorBIBO.wrap(instance);
            ResponseAPDU get_nok = bibo.transmit(new CommandAPDU(0x00, 0x42, 0x00, 0x00, 256));
            assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, get_nok.getSW());

            GPSession gp = GPSession.connect(bibo, new pro.javacard.capfile.AID(AIDUtil.bytes(appletAID)));
            gp.openSecureChannel(pk, null, null, EnumSet.of(GPSession.APDUMode.ENC));
            byte[] cgram = pk.encrypt(GPCrypto.pad80("Hello, World!".getBytes(StandardCharsets.UTF_8), 16), new byte[]{0x00, 0x00});
            ResponseAPDU set = gp.transmit(new CommandAPDU(0x80, 0x42, 0x00, 0x00, cgram));
            assertEquals(0x9000, set.getSW());
            ResponseAPDU get = bibo.transmit(new CommandAPDU(0x00, 0x42, 0x00, 0x00, 256));
            assertEquals(0x9000, get.getSW());
            assertArrayEquals("Hello, World!".getBytes(StandardCharsets.UTF_8), get.getData());

            ResponseAPDU get_mem = bibo.transmit(new CommandAPDU(0x00, 0x07, 0x00, 0x00, 256));
            assertEquals(0x9000, get_mem.getSW());
            assertEquals(6, get_mem.getData().length);
        }
    }

    @Test
    public void globalPlatformInstallTest() throws Exception {
        JavaCardEngine sim = JavaCardEngine.create();

        AID appletAID = AIDUtil.create("010203040506070809");
        pro.javacard.capfile.AID jcaid = new pro.javacard.capfile.AID(AIDUtil.bytes(appletAID));
        sim.loadApplet(appletAID, appletAID, GlobalPlatformTestApplet.class);

        PlaintextKeys pk = PlaintextKeys.defaultKey();
        try (EngineSession instance = sim.connect()) {
            APDUBIBO bibo = SimulatorBIBO.wrap(instance);
            ResponseAPDU get_nok = bibo.transmit(new CommandAPDU(0x00, 0x42, 0x00, 0x00, 256));
            assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, get_nok.getSW());

            //GPSession gp = GPSession.connect(bibo, new pro.javacard.capfile.AID(AIDUtil.bytes(appletAID)));
            GPSession gp = GPSession.discover(bibo);
            gp.openSecureChannel(pk, null, null, EnumSet.of(GPSession.APDUMode.ENC));
            gp.installAndMakeSelectable(jcaid, jcaid, jcaid, EnumSet.noneOf(GPRegistryEntry.Privilege.class), new byte[4]);

            // Now try talking to that applet
            // Note: we need a new key object, as the keys get diversified by channel opening
            PlaintextKeys pk2 = PlaintextKeys.defaultKey();

            gp = GPSession.connect(bibo, new pro.javacard.capfile.AID(AIDUtil.bytes(appletAID)));
            gp.openSecureChannel(pk2, null, null, EnumSet.of(GPSession.APDUMode.ENC));
            byte[] cgram = pk2.encrypt(GPCrypto.pad80("Hello, World!".getBytes(StandardCharsets.UTF_8), 16), new byte[]{0x00, 0x01});
            ResponseAPDU set = gp.transmit(new CommandAPDU(0x80, 0x42, 0x00, 0x00, cgram));
            assertEquals(0x9000, set.getSW());
            set = gp.transmit(new CommandAPDU(0x80, 0x42, 0x00, 0x00, cgram));
            assertEquals(0x9000, set.getSW());
            ResponseAPDU get = bibo.transmit(new CommandAPDU(0x00, 0x42, 0x00, 0x00, 256));
            assertEquals(0x9000, get.getSW());
            assertArrayEquals("Hello, World!".getBytes(StandardCharsets.UTF_8), get.getData());

            PlaintextKeys pk3 = PlaintextKeys.defaultKey();
            gp = GPSession.connect(bibo, new pro.javacard.capfile.AID(AIDUtil.bytes(GlobalPlatformApplet.OPEN_AID)));
            gp.openSecureChannel(pk3, null, null, EnumSet.of(GPSession.APDUMode.ENC));
            gp.deleteAID(jcaid, false);
        }
    }
    public static class SimulatorBIBO implements BIBO {
        final EngineSession sim;

        public SimulatorBIBO(EngineSession sim) {
            this.sim = sim;
        }

        @Override
        public byte[] transceive(byte[] bytes) throws BIBOException {
            System.out.println(">> " + Hex.toHexString(bytes));
            byte[] response = sim.transmitCommand(bytes);
            System.out.println("<< " + Hex.toHexString(response));
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
}
