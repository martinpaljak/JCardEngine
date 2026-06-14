// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
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

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;

public final class SCP03SecureChannel extends EngineSecureChannel {
    private static final Logger log = LoggerFactory.getLogger(SCP03SecureChannel.class);
    private final boolean s16;
    private final byte[] SCP;

    private final byte[] ssc = new byte[3];
    private final byte[] chaining = new byte[16];
    private final byte[] enc_counter = new byte[16];

    private byte[] ctx; // needed twice

    public SCP03SecureChannel(boolean s16) {
        this.s16 = s16;
        this.SCP = new byte[]{0x03, (byte) (0x70 | (s16 ? 0x01 : 0x00))};
    }

    public SCP03SecureChannel() {
        this(false);
    }

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
            // P2 (Key Identifier) unused for SCP03 master-key selection. GPC v2.3.1 D.4.1.4.
            if (buffer[ISO7816.OFFSET_P2] != 0x00) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            if (buffer[ISO7816.OFFSET_LC] != (s16 ? 16 : 8)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            resetSession();
            // SCP03 Amd D v1.2 6.2.2.1: advance the per-key-set sequence counter at INITIALIZE
            // UPDATE so each card challenge is unique; reject when it would overflow.
            if (Arrays.equals(ssc, Hex.decode("FFFFFF"))) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            GPCrypto.buffer_increment(ssc);
            byte[] kdd = sessionKDD();
            PlaintextKeys keys = initializeMasterKey(buffer[ISO7816.OFFSET_P1]);
            keys.diversify(GPSecureChannelVersion.SCP.SCP03, kdd);
            byte[] kdf_ctx = GPUtils.concatenate(ssc, AIDUtil.bytes(Simulator.current().getAID()));
            byte[] host_challenge = Arrays.copyOfRange(apdu.getBuffer(), ISO7816.OFFSET_CDATA, ISO7816.OFFSET_CDATA + (s16 ? 16 : 8));
            byte[] card_challenge = keys.scp3_kdf(GPCardKeys.KeyPurpose.ENC, GPCrypto.scp03_kdf_blocka((byte) 0x02, s16 ? 128 : 64), kdf_ctx, s16 ? 16 : 8);
            ctx = GPUtils.concatenate(host_challenge, card_challenge);
            macKey = keys.getSessionKey(GPCardKeys.KeyPurpose.MAC, ctx);
            encKey = keys.getSessionKey(GPCardKeys.KeyPurpose.ENC, ctx);
            byte[] cryptogram = GPCrypto.scp03_kdf(macKey, (byte) 0x00, ctx, s16 ? 128 : 64);
            byte[] resp = GPUtils.concatenate(kdd, new byte[]{currentMasterKey.kvn()}, SCP, card_challenge, cryptogram, ssc);
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
            // SCP03 Amendment D v1.2 7.1.2.3 Table 7-6: C-DECRYPTION implies C-MAC, R-ENCRYPTION implies R-MAC.
            if (((buffer[ISO7816.OFFSET_P1] & SecureChannel.C_DECRYPTION) != 0 && (buffer[ISO7816.OFFSET_P1] & SecureChannel.C_MAC) == 0)
                    || ((buffer[ISO7816.OFFSET_P1] & SecureChannel.R_ENCRYPTION) != 0 && (buffer[ISO7816.OFFSET_P1] & SecureChannel.R_MAC) == 0)) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            if (buffer[ISO7816.OFFSET_P2] != 0x00) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            if (buffer[ISO7816.OFFSET_LC] != (s16 ? 16 : 8) * 2) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            // No session keys means no preceding INITIALIZE UPDATE. GPC v2.3.1 E.1.2.1.
            if (macKey == null) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            process_mac(buffer, ISO7816.OFFSET_CLA, apdu.getIncomingLength() + ISO7816.OFFSET_CDATA);

            // Verify challenge
            byte[] host_cryptogram = GPCrypto.scp03_kdf(macKey, (byte) 0x01, ctx, s16 ? 128 : 64);
            if (!Arrays.equals(host_cryptogram, Arrays.copyOfRange(apdu.getBuffer(), ISO7816.OFFSET_CDATA, ISO7816.OFFSET_CDATA + host_cryptogram.length))) {
                log.error("Host cryptogram check failed");
                ISOException.throwIt((short) 0x6300);
            }
            state = (byte) (SecureChannel.AUTHENTICATED | buffer[ISO7816.OFFSET_P1]);
            log.debug("Secure channel #{} state is now {}", Hex.toHexString(ssc), String.format("%02x", state));
            return 0;
        } else {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            return 0;
        }
    }

    void process_mac(byte[] buffer, int offset, int length) {
        // FIXME: handle chaining
        final int maclen = s16 ? 16 : 8;
        byte[] mac = Arrays.copyOfRange(buffer, offset + length - maclen, offset + length);
        log.trace("mac: {}", Hex.toHexString(mac));
        byte[] payload = Arrays.copyOfRange(buffer, offset + ISO7816.OFFSET_CDATA, offset + length - maclen);
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        bo.writeBytes(chaining);
        bo.write(buffer[offset + ISO7816.OFFSET_CLA]);
        bo.write(buffer[offset + ISO7816.OFFSET_INS]);
        bo.write(buffer[offset + ISO7816.OFFSET_P1]);
        bo.write(buffer[offset + ISO7816.OFFSET_P2]);
        bo.write(buffer[offset + ISO7816.OFFSET_LC]);
        bo.writeBytes(payload);
        byte[] cmac_input = bo.toByteArray();
        log.trace("mac input: {}", Hex.toHexString(cmac_input));
        byte[] cmac = GPCrypto.aes_cmac(macKey, cmac_input, 128);
        // set new chaining value
        System.arraycopy(cmac, 0, chaining, 0, chaining.length);
        byte[] check = Arrays.copyOf(cmac, maclen);
        if (!Arrays.equals(check, mac)) {
            log.error("MAC mismatch: calculated {}, presented {}", Hex.toHexString(check), Hex.toHexString(mac));
            resetSecurity();
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    @Override
    public short wrap(byte[] bytes, short i, short i1) throws ISOException {
        throw new UnsupportedOperationException("SecureChannel.wrap()");
    }

    @Override
    public short unwrap(byte[] bytes, short offset, short length) throws ISOException {
        requireAuthenticated();
        log.trace("Unwrapping ...");
        final int maclen = s16 ? 16 : 8;
        byte[] cryptogram = Arrays.copyOfRange(bytes, offset + ISO7816.OFFSET_CDATA, offset + length - maclen);

        try {
            if ((state & SecureChannel.C_MAC) == SecureChannel.C_MAC) {
                process_mac(bytes, offset, length);
            }
            log.trace("Cryptogram len={} {}", cryptogram.length, Hex.toHexString(cryptogram));
            if ((bytes[offset + ISO7816.OFFSET_CLA] & 0x04) == 0x04 && (state & SecureChannel.C_DECRYPTION) == SecureChannel.C_DECRYPTION) {
                // GPC v2.3.1 Amd D 6.2.6: increment the counter even with no data field, to stay
                // in sync with GPPro's wrapper.
                GPCrypto.buffer_increment(enc_counter);
                if (cryptogram.length > 0) {
                    byte[] iv = GPCrypto.aes_cbc(enc_counter, encKey, new byte[16]);
                    byte[] payload = GPCrypto.aes_cbc_decrypt(cryptogram, encKey, iv);
                    payload = GPCrypto.unpad80(payload);
                    log.trace("Unwrapped: {}", Hex.toHexString(payload));
                    Util.arrayCopyNonAtomic(payload, (short) 0, bytes, (short) (offset + ISO7816.OFFSET_CDATA), (short) payload.length);
                    bytes[offset + ISO7816.OFFSET_LC] = (byte) payload.length; // TODO: extlen
                    return (short) (ISO7816.OFFSET_CDATA + payload.length);
                }
                // Empty case-1 APDU: no cryptogram, fall through to MAC-strip path.
            }
            // Strip MAC if present
            if ((state & SecureChannel.C_MAC) == SecureChannel.C_MAC) {
                bytes[offset + ISO7816.OFFSET_LC] -= maclen;
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
        if (length % 16 != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        requireAuthenticated();
        try {
            // SCP03 uses static DEK
            byte[] result = GPCrypto.aes_cbc_decrypt(Arrays.copyOfRange(buffer, offset, offset + length), currentMasterKey.value(KeySet.KID_DEK), new byte[16]);
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
        zeroize(encKey, macKey, chaining, enc_counter);
    }

    @Override
    void resetCounter() {
        zeroize(ssc);
    }

    // GPC v2.3.1 Amd D 6.2.5/6.2.7: R-MAC = 8 bytes (S8) or 16 (S16); R-ENCRYPTION pads up to +16.
    @Override
    short maxResponseLength() {
        short max = 256;
        if ((state & SecureChannel.R_MAC) != 0) {
            max -= s16 ? 16 : 8;
        }
        if ((state & SecureChannel.R_ENCRYPTION) != 0) {
            max -= 16;
        }
        return max;
    }
}
