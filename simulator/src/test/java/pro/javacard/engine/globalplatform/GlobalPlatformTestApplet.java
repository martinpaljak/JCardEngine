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

import javacard.framework.*;
import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

public final class GlobalPlatformTestApplet extends Applet {
    public static final byte INS_INITIALIZE_UPDATE = 0x50; // GP
    public static final byte INS_EXTERNAL_AUTHENTICATE = ISO7816.INS_EXTERNAL_AUTHENTICATE;

    byte[] data = new byte[128];

    public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
        short offset = bOffset;
        offset += (short) (bArray[offset] + 1); // instance AID
        offset += (short) (bArray[offset] + 1); // privileges - expect none
        new GlobalPlatformTestApplet(bArray, (short) (offset + 1), bArray[offset]).register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }


    private GlobalPlatformTestApplet(byte[] parameters, short parametersOffset, byte parametersLength) {
        if (parametersLength > 0) {
            Util.arrayCopy(parameters, parametersOffset, data, (short) 1, parametersLength);
            data[0] = parametersLength;
        }
    }

    @Override
    public void deselect() {
        GPSystem.getSecureChannel().resetSecurity();
    }

    @Override
    public boolean select() {
        return true;
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        if (selectingApplet())
            return;
        byte[] buffer = apdu.getBuffer();

        // Filter out GP commands to pass to SecureChannel. SecureChannel validates the CLA.
        if (buffer[ISO7816.OFFSET_INS] == INS_INITIALIZE_UPDATE || buffer[ISO7816.OFFSET_INS] == INS_EXTERNAL_AUTHENTICATE) {
            short offset = GPSystem.getSecureChannel().processSecurity(apdu);
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, offset);
        } else if (apdu.isSecureMessagingCLA() && ((buffer[ISO7816.OFFSET_CLA] & 0x80) == 0x80)) {
            // Custom CLA
            SecureChannel sec = GPSystem.getSecureChannel();
            // Require encryption
            if ((sec.getSecurityLevel() & (SecureChannel.AUTHENTICATED | SecureChannel.C_DECRYPTION)) != (SecureChannel.AUTHENTICATED | SecureChannel.C_DECRYPTION)) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            short inlen = apdu.setIncomingAndReceive();
            // Unwrap in place to APDU buffer, keeping the APDU header intact
            sec.unwrap(buffer, (short) 0, (short) (apdu.getOffsetCdata() + inlen));
            short len = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);

            switch (buffer[ISO7816.OFFSET_INS]) {
                case 0x42:
                    if (len < 7 || len > 0x7f)
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    try {
                        JCSystem.beginTransaction();
                        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, data, (short) 1, len);
                        data[0] = (byte) len;
                    } finally {
                        if (JCSystem.getTransactionDepth() == 1) {
                            JCSystem.commitTransaction();
                        }
                    }
                    return;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } else {
            switch (buffer[ISO7816.OFFSET_INS]) {
                case 0x42:
                    // Delete everything.
                    if (JCSystem.isObjectDeletionSupported()) {
                        JCSystem.requestObjectDeletion();
                    }
                    if (data[0] == 0) {
                        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
                    }
                    if (GPSystem.getCardState() != GPSystem.CARD_SECURED) {
                        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    }
                    Util.arrayCopyNonAtomic(data, (short) 1, buffer, (short) 0, data[0]);
                    apdu.setOutgoingAndSend((short) 0, data[0]);
                    return;
                case 0x07:
                    // get memory info
                    Util.setShort(buffer, (short) 0, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT));
                    Util.setShort(buffer, (short) 2, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET));
                    Util.setShort(buffer, (short) 4, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT));
                    apdu.setOutgoingAndSend((short) 0, (short) 6);
                    return;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        }
    }
}
