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
package pro.javacard.engine.globalplatform;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlvParser;
import javacard.framework.*;
import org.bouncycastle.util.encoders.Hex;
import org.globalplatform.GPSystem;
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
            byte[] payload = Arrays.copyOfRange(buffer, ISO7816.OFFSET_CDATA, ISO7816.OFFSET_CDATA + buffer[ISO7816.OFFSET_LC]);
            System.err.println("payload: " + Hex.toHexString(payload));

            if (buffer[ISO7816.OFFSET_INS] == (byte) 0xe6) {
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
                // Extract application parameters from parameters
                if (parameters.length > 0) {
                    var tags = new BerTlvParser().parse(parameters);
                    var c9 = tags.find(new BerTag(0xC9));
                    parameters = c9.getBytesValue();
                }
                Simulator.current().internalInstallApplet(instanceaid, appletClass, privileges, parameters, true);
                buffer[0] = 0x00;
                apdu.setOutgoingAndSend((short) 0, (short) 1);
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
