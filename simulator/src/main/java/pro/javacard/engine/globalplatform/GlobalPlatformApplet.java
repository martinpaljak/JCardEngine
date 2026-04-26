// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import com.licel.jcardsim.base.ApplicationInstance;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.*;
import pro.javacard.tlv.TLV;
import pro.javacard.tlv.Tag;
import org.bouncycastle.util.encoders.Hex;
import org.globalplatform.Application;
import org.globalplatform.GPSystem;
import org.globalplatform.Personalization;
import org.globalplatform.SecureChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

// This is a virtual applet implementing the OPEN (GlobalPlatform Card Manager)
public class GlobalPlatformApplet extends Applet {

    private static final Logger log = LoggerFactory.getLogger(GlobalPlatformApplet.class);

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        short offset = bOffset;
        offset += (short) (bArray[offset] + 1); // instance AID
        offset += (short) (bArray[offset] + 1); // privileges - expect none
        GlobalPlatformApplet applet = new GlobalPlatformApplet(bArray, (short) (offset + 1), bArray[offset]);
        applet.register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    private GlobalPlatformApplet(byte[] parameters, short parametersOffset, byte parametersLength) {
    }

    byte[] FCI = Hex.decode("6F108408A000000151000000A5049F6501FF");
    public static final AID OPEN_AID = AIDUtil.create("A000000151000000");

    @Override
    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        if (selectingApplet()) {
            // return with minimal FCI
            Util.arrayCopyNonAtomic(FCI, (short) 0, buffer, (short) 0, (short) FCI.length);
            apdu.setOutgoingAndSend((short) 0, (short) FCI.length);
            return;
        }

        // Secure channel opening
        if (buffer[ISO7816.OFFSET_INS] == 0x50 || buffer[ISO7816.OFFSET_INS] == (byte) 0x82) {
            short len = GPSystem.getSecureChannel().processSecurity(apdu);
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
            return;
        }

        if ((GPSystem.getSecureChannel().getSecurityLevel() & SecureChannel.AUTHENTICATED) == SecureChannel.AUTHENTICATED) {

            short len = apdu.setIncomingAndReceive();
            GPSystem.getSecureChannel().unwrap(buffer, ISO7816.OFFSET_CLA, (short) (ISO7816.OFFSET_CDATA + len));
            byte[] payload = Arrays.copyOfRange(buffer, ISO7816.OFFSET_CDATA, ISO7816.OFFSET_CDATA + (buffer[ISO7816.OFFSET_LC] & 0xFF));

            if (buffer[ISO7816.OFFSET_INS] == (byte) 0xe6) {
                if (buffer[ISO7816.OFFSET_P1] == (byte) 0x20) {
                    // INSTALL [for personalization]
                    List<byte[]> cmd;
                    try {
                        cmd = parse_lv(payload);
                    } catch (RuntimeException e) {
                        log.warn("Malformed INSTALL [for personalization] data");
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        return;
                    }
                    if (cmd.size() < 3) {
                        log.warn("INSTALL [for personalization] missing Application AID");
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        return;
                    }
                    dump_lv(cmd);
                    var targetAidBytes = cmd.get(2);
                    if (targetAidBytes.length < 5 || targetAidBytes.length > 16) {
                        log.warn("INSTALL [for personalization] invalid Application AID length: {}", targetAidBytes.length);
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        return;
                    }
                    var targetAid = AIDUtil.create(targetAidBytes);
                    // Verify target applet exists and implements Personalization or Application
                    var appInstance = ((Simulator) Simulator.current()).lookupApplet(targetAid);
                    if (appInstance == null) {
                        log.warn("Personalization target applet not found: {}", AIDUtil.toString(targetAid));
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    }
                    Applet targetApplet = appInstance.getApplet();
                    if (!(targetApplet instanceof Personalization) && !(targetApplet instanceof Application)) {
                        log.warn("Target applet does not implement Personalization or Application interface");
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    }
                    Simulator.current().getGlobalPlatform().setPersonalizationTarget(targetAid);
                    buffer[0] = 0x00;
                    apdu.setOutgoingAndSend((short) 0, (short) 1);
                    return;
                }
                // INSTALL [for install and make selectable]
                var cmd = parse_lv(payload);
                dump_lv(cmd);

                var pkg = AIDUtil.create(cmd.get(0));
                var app = AIDUtil.create(cmd.get(1));
                var instanceaid = AIDUtil.create(cmd.get(2));
                var privileges = cmd.get(3);
                var parameters = cmd.get(4);
                var appletClass = Simulator.current().getGlobalPlatform().locateApplet(pkg, app);

                if (appletClass == null) {
                    log.warn("Applet not found");
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                // Extract C9 tag value from install parameters
                if (parameters.length > 0) {
                    List<TLV> tags = TLV.parse(parameters);
                    TLV c9 = TLV.find(tags, Tag.ber(0xC9)).orElse(null);
                    parameters = c9 != null ? c9.value() : new byte[0];
                }
                Simulator.current().internalInstallApplet(instanceaid, appletClass, privileges, parameters, true);
                buffer[0] = 0x00;
                apdu.setOutgoingAndSend((short) 0, (short) 1);
                return;
            } else if (buffer[ISO7816.OFFSET_INS] == (byte) 0xe2) {
                // STORE DATA - indirect personalization
                var gp = Simulator.current().getGlobalPlatform();
                AID targetAid = gp.getPersonalizationTarget();
                if (targetAid == null) {
                    log.warn("STORE DATA: no personalization target set");
                    ISOException.throwIt((short) 0x6985); // conditions not satisfied
                }
                var appInstance = ((Simulator) Simulator.current()).lookupApplet(targetAid);
                if (appInstance == null) {
                    log.warn("STORE DATA: personalization target applet not found");
                    gp.setPersonalizationTarget(null);
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                Applet targetApplet = appInstance.getApplet();
                // Build full STORE DATA command: CLA + INS + P1 + P2 + Lc + data
                short cmdLen = (short) (ISO7816.OFFSET_CDATA + payload.length);
                byte[] cmdBuffer = new byte[cmdLen];
                Util.arrayCopyNonAtomic(buffer, (short) 0, cmdBuffer, (short) 0, cmdLen);

                // GP 2.2.1 Section 7.3.3 / GP API Personalization javadoc:
                // "Upon invocation of this method, the Java Card VM performs a context switch."
                // Push target applet context so JCSystem.getAID() returns the target's AID
                // and JCSystem.getPreviousContextAID() returns the Security Domain's AID.
                var sim = (Simulator) Simulator.current();
                AID registryAid = appInstance.getAID();

                if (targetApplet instanceof Personalization perso) {
                    byte[] outBuffer = new byte[256];
                    short outLen;
                    sim.pushContext(registryAid);
                    try {
                        outLen = perso.processData(cmdBuffer, (short) 0, cmdLen, outBuffer, (short) 0);
                    } finally {
                        sim.popContext();
                    }
                    // If last block (P1 bit 7 set), clear personalization target
                    if ((buffer[ISO7816.OFFSET_P1] & (byte) 0x80) != 0) {
                        gp.setPersonalizationTarget(null);
                    }
                    if (outLen > 0) {
                        Util.arrayCopyNonAtomic(outBuffer, (short) 0, buffer, (short) 0, outLen);
                        apdu.setOutgoingAndSend((short) 0, outLen);
                    } else {
                        buffer[0] = 0x00;
                        apdu.setOutgoingAndSend((short) 0, (short) 1);
                    }
                } else if (targetApplet instanceof Application app) {
                    sim.pushContext(registryAid);
                    try {
                        app.processData(cmdBuffer, (short) 0, cmdLen);
                    } finally {
                        sim.popContext();
                    }
                    // If last block (P1 bit 7 set), clear personalization target
                    if ((buffer[ISO7816.OFFSET_P1] & (byte) 0x80) != 0) {
                        gp.setPersonalizationTarget(null);
                    }
                    buffer[0] = 0x00;
                    apdu.setOutgoingAndSend((short) 0, (short) 1);
                } else {
                    log.warn("Target applet does not implement Personalization or Application");
                    gp.setPersonalizationTarget(null);
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                return;
            } else if (buffer[ISO7816.OFFSET_INS] == (byte) 0xe4) {
                var aid = AIDUtil.create(Arrays.copyOfRange(payload, 2, payload.length));
                try {
                    Simulator.current().internalDeleteApplet(aid);
                } catch (Exception e) {
                    // Do nothing, intentionally
                }
                buffer[0] = 0x00;
                apdu.setOutgoingAndSend((short) 0, (short) 1);
                return;
            }
        }
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }

    static List<byte[]> parse_lv(byte[] data) {
        var result = new ArrayList<byte[]>();
        var bb = ByteBuffer.wrap(data);
        while (bb.position() < bb.limit()) {
            int len = bb.get() & 0xFF;
            var value = new byte[len];
            bb.get(value);
            result.add(value);
        }
        return result;
    }

    static void dump_lv(List<byte[]> lv) {
        for (var f : lv) {
            log.info("[0x%02X] %s".formatted(f.length, Hex.toHexString(f)));
        }
    }
}
