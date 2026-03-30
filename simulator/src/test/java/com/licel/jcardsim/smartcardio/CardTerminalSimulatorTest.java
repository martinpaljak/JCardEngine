package com.licel.jcardsim.smartcardio;

import com.licel.jcardsim.samples.DualInterfaceApplet;
import com.licel.jcardsim.samples.HelloWorldApplet;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;

import javax.smartcardio.*;

import static org.junit.jupiter.api.Assertions.*;

// Tests the bridge between JavaCardEngine and pcsc-sim (SynthesizedCardTerminal).
// pcsc-sim terminal/card behavior is tested in apdu4j itself.
public class CardTerminalSimulatorTest {
    private static final ATR ETALON_ATR = new ATR(Hex.decode("3B80800101"));
    private static final String HELLO_AID = "010203040506070809";
    private static final String DUAL_AID = "D0000CAFE00001";

    @Test
    void testTerminalBridge() throws CardException {
        var engine = JavaCardEngine.create();
        engine.installApplet(AIDUtil.create(HELLO_AID), HelloWorldApplet.class, Hex.decode("0F0F"));
        var terminal = engine.toTerminal();

        var card = terminal.connect("T=1");
        assertEquals(ETALON_ATR, card.getATR());
        assertEquals("T=1", card.getProtocol());

        // select and exchange APDUs via javax.smartcardio
        var channel = card.getBasicChannel();
        var response = channel.transmit(new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 4, 0, Hex.decode(HELLO_AID)));
        assertEquals(0x9000, response.getSW());

        response = channel.transmit(new CommandAPDU(0x01, 0x01, 0x00, 0x00));
        assertEquals(0x9000, response.getSW());
        assertEquals("Hello world !", new String(response.getData()));
    }

    @Test
    void testTerminalFactory() throws CardException {
        var engine = JavaCardEngine.create();
        engine.installApplet(AIDUtil.create(HELLO_AID), HelloWorldApplet.class);
        var factory = engine.toTerminalFactory();
        var terminal = factory.terminals().list().get(0);

        assertEquals("jcardengine.Terminal", terminal.getName());
        assertTrue(terminal.isCardPresent());

        var card = terminal.connect("T=1");
        var channel = card.getBasicChannel();
        channel.transmit(new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 4, 0, Hex.decode(HELLO_AID)));
        var response = channel.transmit(new CommandAPDU(0x01, 0x01, 0x00, 0x00));
        assertEquals(0x9000, response.getSW());
    }

    @Test
    void testReconnectAfterResetDisconnect() throws CardException {
        var engine = JavaCardEngine.create();
        engine.installApplet(AIDUtil.create(HELLO_AID), HelloWorldApplet.class, Hex.decode("0F0F"));
        var terminal = engine.toTerminal();

        // first session - store echo data in CLEAR_ON_RESET transient memory
        var card = terminal.connect("T=1");
        var channel = card.getBasicChannel();
        channel.transmit(new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 4, 0, Hex.decode(HELLO_AID)));
        var echoData = "TestData".getBytes();
        var response = channel.transmit(new CommandAPDU(0x01, 0x01, 0x01, 0x00, echoData));
        assertEquals(0x9000, response.getSW());
        assertArrayEquals(echoData, response.getData());

        // disconnect with reset - transient memory should be cleared
        card.disconnect(true);
        assertTrue(terminal.isCardPresent()); // factory mode - card stays

        // second session - echo should return default (hello world), not our stored data
        card = terminal.connect("T=1");
        channel = card.getBasicChannel();
        channel.transmit(new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 4, 0, Hex.decode(HELLO_AID)));
        response = channel.transmit(new CommandAPDU(0x01, 0x01, 0x00, 0x00));
        assertEquals(0x9000, response.getSW());
        assertEquals("Hello world !", new String(response.getData()));
    }

    @Test
    void testContactlessProtocol() throws CardException {
        var engine = JavaCardEngine.create();
        engine.installApplet(AIDUtil.create(DUAL_AID), DualInterfaceApplet.class);

        // connect as contactless via pcsc-sim terminal
        var terminal = engine.toTerminal("CL Reader");
        var card = terminal.connect("T=CL");
        var channel = card.getBasicChannel();

        // select applet
        channel.transmit(new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 4, 0, Hex.decode(DUAL_AID)));

        // INS_INFO returns protocol byte - should be contactless
        var response = channel.transmit(new CommandAPDU(0x80, 0x04, 0x00, 0x00));
        assertEquals(0x9000, response.getSW());
        byte protocol = response.getData()[0];
        assertEquals(APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A | APDU.PROTOCOL_T1, protocol);

        // write should fail on contactless interface
        response = channel.transmit(new CommandAPDU(0x80, 0x02, 0x00, 0x00, new byte[]{(byte) 0xCA, (byte) 0xFE}));
        assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, response.getSW());
    }

    @Test
    void testContactProtocol() throws CardException {
        var engine = JavaCardEngine.create();
        engine.installApplet(AIDUtil.create(DUAL_AID), DualInterfaceApplet.class);

        var terminal = engine.toTerminal("Contact Reader");
        var card = terminal.connect("T=1");
        var channel = card.getBasicChannel();

        channel.transmit(new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 4, 0, Hex.decode(DUAL_AID)));

        // INS_INFO - should be contact (T=1, media default)
        var response = channel.transmit(new CommandAPDU(0x80, 0x04, 0x00, 0x00));
        assertEquals(0x9000, response.getSW());
        byte protocol = response.getData()[0];
        assertEquals(APDU.PROTOCOL_T1, protocol);

        // write should succeed on contact interface
        response = channel.transmit(new CommandAPDU(0x80, 0x02, 0x00, 0x00, new byte[]{(byte) 0xCA, (byte) 0xFE}));
        assertEquals(0x9000, response.getSW());

        // read it back
        response = channel.transmit(new CommandAPDU(0x80, 0x00, 0x00, 0x00));
        assertEquals(0x9000, response.getSW());
        assertArrayEquals(new byte[]{(byte) 0xCA, (byte) 0xFE}, response.getData());
    }
}
