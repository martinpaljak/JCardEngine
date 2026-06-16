// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2015 Robert Bachmann
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim;

import apdu4j.core.CommandAPDU;
import apdu4j.pcsc.sim.SynthesizedCardTerminal;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.samples.HelloWorldApplet;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.testng.annotations.Test;
import pro.javacard.engine.JavaCardEngine;

import javax.smartcardio.CardException;
import java.time.Duration;

import static org.testng.Assert.*;

/**
 * Contains all listing from the documentation
 */
@SuppressWarnings({"deprecation", "removal"})
public class DocumentationCodeSamplesTest implements SmartCardTest {

    @Test
    public void testCodeListingReadme() {
        // 1. Create engine and install applet
        var engine = JavaCardEngine.create();
        var appletAID = AIDUtil.create("F000000001");
        engine.installApplet(appletAID, HelloWorldApplet.class);

        // 2. Open BIBO session and send APDU
        try (var bibo = engine.connect()) {
            bibo.transmit(AIDUtil.select(appletAID));
            var response = bibo.transmit(new CommandAPDU(0x00, 0x01, 0x00, 0x00));

            // 3. Check response status word
            assertSW(0x9000, response.getSW());
        }
    }

    @Test
    public void testCodeListing1() {
        // 1. Create simulator
        var simulator = new Simulator();
        var appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, HelloWorldApplet.class);

        // 2. Open BIBO session, select applet, send APDU
        try (var bibo = simulator.connect()) {
            bibo.transmit(AIDUtil.select(appletAID));
            var response = bibo.transmit(new CommandAPDU(0x00, 0x01, 0x00, 0x00));

            // 3. Check response status word
            assertEquals(response.getSW(), 0x9000);
        }
    }

    @Test
    public void testCodeListing2() {
        var simulator = new Simulator();

        var appletAIDBytes = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9};
        var appletAID = new AID(appletAIDBytes, (short) 0, (byte) appletAIDBytes.length);

        simulator.installApplet(appletAID, HelloWorldApplet.class);

        try (var bibo = simulator.connect()) {
            bibo.transmit(AIDUtil.select(appletAID));

            // test NOP
            var response = bibo.transmit(new CommandAPDU(0x00, 0x02, 0x00, 0x00));
            assertEquals(response.getSW(), 0x9000);

            // test hello world from card
            response = bibo.transmit(new CommandAPDU(0x00, 0x01, 0x00, 0x00));
            assertEquals(response.getSW(), 0x9000);
            assertEquals(new String(response.getData()), "Hello world !");

            // test echo
            response = bibo.transmit(new CommandAPDU(0x00, 0x01, 0x01, 0x00, "Hello javacard world !".getBytes()));
            assertEquals(response.getSW(), 0x9000);
            assertEquals(new String(response.getData()), "Hello javacard world !");
        }
    }

    @Test
    public void testCodeListing3() {
        var simulator = new Simulator();

        var appletAIDBytes = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9};
        var appletAID = new AID(appletAIDBytes, (short) 0, (byte) appletAIDBytes.length);

        simulator.installApplet(appletAID, HelloWorldApplet.class);

        try (var bibo = simulator.connect()) {
            bibo.transmit(AIDUtil.select(appletAID));

            // test NOP
            var response = bibo.transmit(new CommandAPDU(0x00, 0x02, 0x00, 0x00));
            assertEquals(response.getSW(), 0x9000);
        }
    }

    @Test
    public void testCodeListing5() throws CardException {
        // 1. Create engine and install applet
        var engine = JavaCardEngine.create();
        var appletAID = AIDUtil.create("F000000001");
        engine.installApplet(appletAID, HelloWorldApplet.class);

        // 2. Get terminal backed by engine
        var terminal = engine.toTerminal();

        // 3. Connect to Card via javax.smartcardio
        var card = terminal.connect("T=1");
        var channel = card.getBasicChannel();

        // 4. Select applet
        channel.transmit(new javax.smartcardio.CommandAPDU(AIDUtil.select(appletAID).getBytes()));

        // 5. Send APDU
        var response = channel.transmit(new javax.smartcardio.CommandAPDU(0x00, 0x01, 0x00, 0x00));

        // 6. Check response status word
        assertEquals(response.getSW(), 0x9000);
    }

    @Test
    public void testCodeListing6() throws CardException {
        // 1. Create engine and install applet
        var engine = JavaCardEngine.create();
        var appletAID = AIDUtil.create("F000000001");
        engine.installApplet(appletAID, HelloWorldApplet.class);

        // 2. Get TerminalFactory backed by engine
        var factory = engine.toTerminalFactory();
        var cardTerminals = factory.terminals();

        // 3. Get terminal
        var terminal = cardTerminals.getTerminal("jcardengine.Terminal");
        assertNotNull(terminal);

        // 4. Card is present via factory mode
        assertTrue(terminal.isCardPresent());
    }

    @Test
    public void testCodeListing7_insert_eject() throws CardException {
        // 1. Create engine and install applet
        var engine = JavaCardEngine.create();
        var appletAID = AIDUtil.create("F000000001");
        engine.installApplet(appletAID, HelloWorldApplet.class);

        // 2. Create terminal - card not yet present
        var terminal = new SynthesizedCardTerminal("My terminal 1");
        assertFalse(terminal.isCardPresent());

        // 3. Present engine to terminal (card appears)
        terminal.presentFactory(protocol -> engine.connectFor(Duration.ZERO, protocol, true), engine.getATR());
        assertTrue(terminal.isCardPresent());

        // 4. Yank card (card disappears)
        terminal.yank();
        assertFalse(terminal.isCardPresent());
    }

    @Test
    public void testCodeListing7_wait_for_insert() throws CardException, InterruptedException {
        // 1. Create terminal - no card yet
        var terminal = new SynthesizedCardTerminal("My terminal 1");
        assertFalse(terminal.isCardPresent());

        // 2. Create engine and install applet
        var engine = JavaCardEngine.create();
        var appletAID = AIDUtil.create("F000000001");
        engine.installApplet(appletAID, HelloWorldApplet.class);

        // 3. Schedule card insertion from another thread
        var thread = new Thread(() -> {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            terminal.presentFactory(protocol -> engine.connectFor(Duration.ZERO, protocol, true), engine.getATR());
        });
        thread.start();

        // 4. Wait for card to appear
        assertTrue(terminal.waitForCardPresent(5000));
        assertTrue(terminal.isCardPresent());

        thread.join();
    }
}
