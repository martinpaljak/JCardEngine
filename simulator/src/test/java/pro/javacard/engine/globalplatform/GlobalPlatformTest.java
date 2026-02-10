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

import apdu4j.core.APDUBIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import pro.javacard.engine.EngineSession;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.engine.SimulatorBIBO;
import pro.javacard.engine.testapplets.GlobalPlatformTestApplet;
import pro.javacard.gp.GPCrypto;
import pro.javacard.gp.GPRegistryEntry;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.keys.PlaintextKeys;

import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class GlobalPlatformTest {

    static Stream<Arguments> scpConfigs() {
        byte[] custom128 = Hex.decode("000102030405060708090A0B0C0D0E0F");
        byte[] custom256 = Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        return Stream.of(
            Arguments.of("SCP02-MAC",           new SCPConfig.SCP02(),            null,       EnumSet.of(GPSession.APDUMode.MAC)),
            Arguments.of("SCP03-MAC",           new SCPConfig.SCP03(),            null,       EnumSet.of(GPSession.APDUMode.MAC)),
            Arguments.of("SCP03-S16-ENC",       new SCPConfig.SCP03(true),        null,       EnumSet.of(GPSession.APDUMode.ENC)),
            Arguments.of("Custom128-SCP03-ENC", new SCPConfig.SCP03(custom128),   custom128,  EnumSet.of(GPSession.APDUMode.ENC)),
            Arguments.of("Custom256-SCP03-ENC", new SCPConfig.SCP03(custom256),   custom256,  EnumSet.of(GPSession.APDUMode.ENC))
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("scpConfigs")
    void testSCPInstallDelete(String name, SCPConfig config, byte[] masterKey,
                               EnumSet<GPSession.APDUMode> mode) throws Exception {
        JavaCardEngine sim = new JavaCardEngine.Builder()
                .withSCP(config)
                .build();
        AID appletAID = AIDUtil.create("010203040506070809");
        pro.javacard.capfile.AID jcaid = new pro.javacard.capfile.AID(AIDUtil.bytes(appletAID));
        sim.loadApplet(appletAID, appletAID, GlobalPlatformTestApplet.class);

        PlaintextKeys pk = masterKey != null ? PlaintextKeys.fromMasterKey(masterKey) : PlaintextKeys.defaultKey();
        try (EngineSession instance = sim.connect()) {
            APDUBIBO bibo = SimulatorBIBO.wrap(instance);
            GPSession gp = GPSession.discover(bibo);
            gp.openSecureChannel(pk, null, null, mode);
            gp.installAndMakeSelectable(jcaid, jcaid, jcaid, EnumSet.noneOf(GPRegistryEntry.Privilege.class), new byte[4]);

            PlaintextKeys pk2 = masterKey != null ? PlaintextKeys.fromMasterKey(masterKey) : PlaintextKeys.defaultKey();
            gp = GPSession.discover(bibo);
            gp.openSecureChannel(pk2, null, null, mode);
            gp.deleteAID(jcaid, false);
        }
    }

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
}
