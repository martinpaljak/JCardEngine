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

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import org.globalplatform.SecureChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.gp.GPCardKeys;
import pro.javacard.gp.GPCrypto;
import pro.javacard.gp.GPSecureChannelVersion;
import pro.javacard.gp.GPUtils;
import pro.javacard.gptool.keys.PlaintextKeys;

import java.security.GeneralSecurityException;
import java.util.Arrays;

public class SCP03SecureChannelImpl implements SecureChannel {

    public static final byte[] kdd = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    private static final Logger log = LoggerFactory.getLogger(SCP03SecureChannelImpl.class);

    private static byte state = SecureChannel.NO_SECURITY_LEVEL;

    @Override
    public short processSecurity(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        // Or not STATE_FULL_INCOMING
        if (apdu.getCurrentState() == APDU.STATE_INITIAL) {
            apdu.setIncomingAndReceive();
        }

        PlaintextKeys keys = PlaintextKeys.defaultKey();
        keys.diversify(GPSecureChannelVersion.SCP.SCP03, kdd);

        if (buffer[ISO7816.OFFSET_INS] == (byte) 0x50) {
            // S8 with 0xFF keys and no pseudorandom
            byte[] host_challenge = Arrays.copyOfRange(apdu.getBuffer(), ISO7816.OFFSET_CDATA, ISO7816.OFFSET_CDATA + 8);
            byte[] card_challenge = GPCrypto.random(8);
            byte[] ctx = GPUtils.concatenate(host_challenge, card_challenge);
            byte[] macKey = keys.getSessionKey(GPCardKeys.KeyPurpose.MAC, ctx);
            byte[] cryptogram = GPCrypto.scp03_kdf(macKey, (byte) 0x00, ctx, 64);
            byte[] resp = GPUtils.concatenate(kdd, new byte[]{(byte) 0xFF}, new byte[]{0x03, 0x00}, card_challenge, cryptogram);
            System.arraycopy(resp, 0, buffer, ISO7816.OFFSET_CDATA, resp.length);
            return (short) resp.length;
        } else if (buffer[ISO7816.OFFSET_INS] == (byte) 0x82) {
            //state = SecureChannel.C_DECRYPTION | SecureChannel.C_MAC | SecureChannel.AUTHENTICATED;
            state = SecureChannel.AUTHENTICATED;
            return 0;
        } else {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            return 0;
        }
    }


    @Override
    public short wrap(byte[] bytes, short i, short i1) throws ISOException {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return 0;
    }

    @Override
    public short unwrap(byte[] bytes, short i, short i1) throws ISOException {
        log.warn("No unwrap implemented for SCP03SecureChannelImpl");
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return 0;
    }

    @Override
    public short decryptData(byte[] buffer, short offset, short length) throws ISOException {
        try {
            byte[] result = GPCrypto.aes_cbc_decrypt(Arrays.copyOfRange(buffer, offset, offset + length), PlaintextKeys.DEFAULT_KEY(), new byte[16]);
            Util.arrayCopyNonAtomic(result, (short) 0, buffer, offset, (short) result.length);
            return (short) result.length;
        } catch (GeneralSecurityException e) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            throw new RuntimeException(e);
        }
    }

    @Override
    public short encryptData(byte[] bytes, short i, short i1) throws ISOException {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return 0;
    }

    @Override
    public void resetSecurity() {
        state = NO_SECURITY_LEVEL;
    }

    @Override
    public byte getSecurityLevel() {
        return state;
    }
}
