// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import apdu4j.core.CommandAPDU;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.gp.GPSession;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static pro.javacard.engine.globalplatform.GPTestUtils.openIsd;

// On-card loading is not supported by this engine: load files are planted by the host via
// Simulator.loadApplet(...) before the simulator runs. The Security Domain therefore actively
// rejects the LOAD APDU and any INSTALL P1 carrying the "for load" bit (b2 = 0x02), with
// SW_FUNC_NOT_SUPPORTED (0x6A81). This is the SOLE legitimate use of hand-rolled CommandAPDU
// in the GP test suite - gp-pro deliberately has no installForLoad surface.
public class DispatchRejectionTest {

    static Stream<Arguments> loadFamilyCases() {
        return Stream.of(
                // GPC v2.3.1 11.5.2.1 / Table 11-41 says P1 b2 = 1 indicates "For load", so the
                // SD must reject on the P1 bit alone regardless of whether the payload is
                // syntactically valid or bogus.
                Arguments.of("INSTALL [for load]", GPSession.INS_INSTALL, GPSession.P1_INSTALL_FOR_LOAD, new byte[]{0x00, 0x00, 0x00, 0x00, 0x00}),
                // P1=0x0E composite: "for load" (0x02) + "for install + make selectable" (0x0C).
                // The load bit alone is enough to reject; the make-selectable half is irrelevant.
                Arguments.of("INSTALL [for load+install+make selectable]", GPSession.INS_INSTALL, (byte) 0x0E, new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
                // Continuation bit (b8 = 0x80) must not mask off the load-bit check. P1=0x82 is
                // the continuation form of INSTALL [for load] and is rejected for the same reason.
                Arguments.of("INSTALL [for load] continuation", GPSession.INS_INSTALL, (byte) 0x82, new byte[]{0x00, 0x00, 0x00, 0x00, 0x00}),
                // GPC v2.3.1 11.6 LOAD (INS 0xE8). Without a preceding INSTALL [for load] this is
                // meaningless on an engine that does not load on card; rejected explicitly rather
                // than left to default 6D00, so a misbehaving GP host gets a deterministic signal.
                Arguments.of("LOAD", GPSession.INS_LOAD, (byte) 0x80, new byte[]{(byte) 0xC4, 0x00})
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("loadFamilyCases")
    void loadFamilyRejectedAtDispatch(String label, byte ins, byte p1, byte[] payload) throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo);
            var r = gp.transmit(new CommandAPDU(GPSession.CLA_GP, ins, p1, 0x00, payload, 256));
            assertEquals(0x6A81, r.getSW(), label + " must be rejected with SW_FUNC_NOT_SUPPORTED (0x6A81) per engine's no-on-card-load rule");
        }
    }
}
