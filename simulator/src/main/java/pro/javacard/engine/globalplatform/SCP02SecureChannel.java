// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import org.bouncycastle.util.encoders.Hex;
import org.globalplatform.SecureChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.gp.GPCardKeys;
import pro.javacard.gp.GPCrypto;
import pro.javacard.gp.GPSecureChannelVersion;
import pro.javacard.gp.GPUtils;
import pro.javacard.gp.keys.PlaintextKeys;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;

public final class SCP02SecureChannel extends EngineSecureChannel {
    private static final Logger log = LoggerFactory.getLogger(SCP02SecureChannel.class);
    private final byte[] SCP = new byte[]{(byte) 0x02};

    public SCP02SecureChannel() {
    }

    private final byte[] ssc = new byte[2];

    private final byte[] card_challenge = new byte[8];
    private final byte[] host_challenge = new byte[8];

    private final byte[] icv = new byte[8];
    boolean open = false;

    private byte[] dekKey;

    @Override
    public short processSecurity(APDU apdu) throws ISOException {
        // Or not STATE_FULL_INCOMING
        if (apdu.getCurrentState() == APDU.STATE_INITIAL) {
            apdu.setIncomingAndReceive();
        }

        byte[] buffer = apdu.getBuffer();

        if (buffer[ISO7816.OFFSET_INS] == INS_INITIALIZE_UPDATE) {
            if (buffer[ISO7816.OFFSET_CLA] != (byte) 0x80) {
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
            }
            // P1 = key version number, used by initializeMasterKey() below to select the key set.
            // P2 (Key Identifier) unused for SCP02 master-key selection. GPC v2.3.1 D.4.1.4.
            if (buffer[ISO7816.OFFSET_P2] != 0x00) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            if (buffer[ISO7816.OFFSET_LC] != 8) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            resetSession();
            byte[] kdd = sessionKDD();
            PlaintextKeys keys = initializeMasterKey(buffer[ISO7816.OFFSET_P1]);
            keys.diversify(GPSecureChannelVersion.SCP.SCP02, kdd);
            var host_challenge = Arrays.copyOfRange(apdu.getBuffer(), ISO7816.OFFSET_CDATA, ISO7816.OFFSET_CDATA + 8);
            var card_challenge = GPUtils.concatenate(ssc, GPCrypto.random(6));
            System.arraycopy(host_challenge, 0, this.host_challenge, 0, host_challenge.length);
            System.arraycopy(card_challenge, 0, this.card_challenge, 0, card_challenge.length);

            macKey = keys.getSessionKey(GPCardKeys.KeyPurpose.MAC, ssc);
            encKey = keys.getSessionKey(GPCardKeys.KeyPurpose.ENC, ssc);
            dekKey = keys.getSessionKey(GPCardKeys.KeyPurpose.DEK, ssc);
            byte[] cryptogram = GPCrypto.mac_3des(GPUtils.concatenate(host_challenge, card_challenge), encKey, new byte[8]);
            byte[] resp = GPUtils.concatenate(kdd, new byte[]{currentMasterKey.kvn()}, SCP, card_challenge, cryptogram);
            System.arraycopy(resp, 0, buffer, ISO7816.OFFSET_CDATA, resp.length);
            return (short) resp.length;
        } else if (buffer[ISO7816.OFFSET_INS] == INS_EXTERNAL_AUTHENTICATE) {
            if (buffer[ISO7816.OFFSET_CLA] != (byte) 0x84) {
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
            }
            // Validate P1
            if ((buffer[ISO7816.OFFSET_P1] & (SecureChannel.AUTHENTICATED | SecureChannel.ANY_AUTHENTICATED)) != 0) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            if ((buffer[ISO7816.OFFSET_P1] & ~(SecureChannel.C_MAC | SecureChannel.C_DECRYPTION | SecureChannel.R_MAC | SecureChannel.R_ENCRYPTION)) != 0) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            // GPC v2.3.1 E.5.2.3 Table E-11: C-DECRYPTION implies C-MAC, R-ENCRYPTION implies R-MAC.
            if (((buffer[ISO7816.OFFSET_P1] & SecureChannel.C_DECRYPTION) != 0 && (buffer[ISO7816.OFFSET_P1] & SecureChannel.C_MAC) == 0)
                    || ((buffer[ISO7816.OFFSET_P1] & SecureChannel.R_ENCRYPTION) != 0 && (buffer[ISO7816.OFFSET_P1] & SecureChannel.R_MAC) == 0)) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            if (buffer[ISO7816.OFFSET_P2] != 0x00) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            if (buffer[ISO7816.OFFSET_LC] != 16) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            process_mac(buffer, ISO7816.OFFSET_CLA, apdu.getIncomingLength() + ISO7816.OFFSET_CDATA);

            // Verify challenge
            byte[] host_cryptogram = GPCrypto.mac_3des(GPUtils.concatenate(card_challenge, host_challenge), encKey, new byte[8]);
            if (!Arrays.equals(host_cryptogram, Arrays.copyOfRange(apdu.getBuffer(), ISO7816.OFFSET_CDATA, ISO7816.OFFSET_CDATA + host_cryptogram.length))) {
                log.error("Host cryptogram check failed");
                ISOException.throwIt((short) 0x6300);
            }
            state = (byte) (SecureChannel.AUTHENTICATED | buffer[ISO7816.OFFSET_P1]);
            GPCrypto.buffer_increment(ssc);
            open = true;
            log.debug("Secure channel #{} state is now {}", Hex.toHexString(ssc), String.format("%02x", state));
            return 0;
        } else {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            return 0;
        }
    }

    void process_mac(byte[] buffer, int offset, int length) {
        // FIXME: handle chaining
        try {
            final int maclen = 8;
            byte[] mac = Arrays.copyOfRange(buffer, offset + length - maclen, offset + length);
            log.trace("mac: {} (session open: {})", Hex.toHexString(mac), open);
            byte[] payload = Arrays.copyOfRange(buffer, offset + ISO7816.OFFSET_CDATA, offset + length - maclen);
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            bo.write(buffer[offset + ISO7816.OFFSET_CLA] | 0x04);
            bo.write(buffer[offset + ISO7816.OFFSET_INS]);
            bo.write(buffer[offset + ISO7816.OFFSET_P1]);
            bo.write(buffer[offset + ISO7816.OFFSET_P2]);
            if (open && ((state & SecureChannel.C_DECRYPTION) == SecureChannel.C_DECRYPTION)) {
                log.trace("MAC payload encrypted");
                byte[] decrypted = des3_cbc_decrypt(payload, encKey, new byte[8]);
                log.trace("Decrypted: {}", Hex.toHexString(decrypted));
                byte[] unpadded = GPCrypto.unpad80(decrypted);
                bo.write(unpadded.length + 8);
                bo.writeBytes(unpadded);
            } else {
                log.trace("MAC payload not encrypted");
                bo.write(buffer[offset + ISO7816.OFFSET_LC]);
                bo.writeBytes(payload);
            }
            byte[] mac_input = bo.toByteArray();
            log.trace("mac input: {} icv: {}", Hex.toHexString(mac_input), Hex.toHexString(icv));
            byte[] check = GPCrypto.mac_des_3des(macKey, mac_input, icv);
            // set new icv
            System.arraycopy(check, 0, icv, 0, icv.length);
            if (!Arrays.equals(check, mac)) {
                log.error("MAC mismatch: calculated {}, presented {}", Hex.toHexString(check), Hex.toHexString(mac));
                resetSecurity();
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }


    @Override
    public short wrap(byte[] bytes, short i, short i1) throws ISOException {
        throw new UnsupportedOperationException("SecureChannel.wrap()");
    }

    private static byte[] des3_cbc_decrypt(byte[] data, byte[] key, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, GPCrypto.des3key(key), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    private static byte[] des3_ecb_decrypt(byte[] data, byte[] key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, GPCrypto.des3key(key));
        return cipher.doFinal(data);
    }

    @Override
    public short unwrap(byte[] bytes, short offset, short length) throws ISOException {
        requireAuthenticated();
        log.trace("Unwrapping ...");
        final int maclen = 8;
        byte[] cryptogram = Arrays.copyOfRange(bytes, offset + ISO7816.OFFSET_CDATA, offset + length - maclen);
        try {
            log.trace("ICV encryption");
            byte[] newicv = GPCrypto.des_ecb(icv, macKey);
            System.arraycopy(newicv, 0, icv, 0, newicv.length);
            if ((state & SecureChannel.C_MAC) == SecureChannel.C_MAC) {
                process_mac(bytes, offset, length);
            }
            log.trace("Cryptogram len={} {}", cryptogram.length, Hex.toHexString(cryptogram));
            if ((bytes[offset + ISO7816.OFFSET_CLA] & 0x04) == 0x04 && (state & SecureChannel.C_DECRYPTION) == SecureChannel.C_DECRYPTION
                    && cryptogram.length > 0) {
                byte[] payload = des3_cbc_decrypt(cryptogram, encKey, new byte[8]);
                payload = GPCrypto.unpad80(payload);
                log.trace("Unwrapped: {}", Hex.toHexString(payload));
                Util.arrayCopyNonAtomic(payload, (short) 0, bytes, (short) (offset + ISO7816.OFFSET_CDATA), (short) payload.length);
                bytes[offset + ISO7816.OFFSET_LC] = (byte) payload.length; // TODO: extlen
                return (short) (offset + ISO7816.OFFSET_CDATA + payload.length);
            }
            // Strip MAC if present (covers both no-ENC and case-1 ENC with empty cryptogram).
            if ((state & SecureChannel.C_MAC) == SecureChannel.C_MAC) {
                bytes[offset + ISO7816.OFFSET_LC] -= 8;
            }
            return (short) (offset + ISO7816.OFFSET_CDATA + (bytes[offset + ISO7816.OFFSET_LC] & 0xFF));
        } catch (GeneralSecurityException e) {
            log.error("Decryption failed", e);
            resetSecurity();
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return 0;
        }
    }

    @Override
    public short decryptData(byte[] buffer, short offset, short length) throws ISOException {
        Objects.requireNonNull(buffer);
        if (length % 8 != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        requireAuthenticated();
        try {
            byte[] result = des3_ecb_decrypt(Arrays.copyOfRange(buffer, offset, offset + length), dekKey);
            log.debug("Decrypted: {}", Hex.toHexString(result));
            Util.arrayCopyNonAtomic(result, (short) 0, buffer, offset, (short) result.length);
            return (short) result.length;
        } catch (GeneralSecurityException e) {
            log.error("Decrypt failed", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public short encryptData(byte[] bytes, short i, short i1) throws ISOException {
        throw new UnsupportedOperationException("SecureChannel.encryptData()");
    }

    // ssc deliberately persists across sessions.
    @Override
    protected void wipeScpState() {
        open = false;
        zeroize(encKey, macKey, dekKey, icv, host_challenge, card_challenge);
    }

    // SCP02 R-MAC is a fixed 8-byte trailer (DES MAC). R-ENCRYPTION is not implemented.
    @Override
    short maxResponseLength() {
        if ((state & SecureChannel.R_MAC) != 0) {
            return (short) 248;
        }
        return (short) 256;
    }
}
