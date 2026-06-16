// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.samples.SymmetricCipherApplet;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

// Split out from SymmetricCipherImplTest because these go strictly through the Simulator interface
public class SymmetricCipherAppletTest {
    /**
     * Test AES encryption/decryption and try DES cipher with AES key type
     */
    @Test
    public void testSymmetricCipherAESEncryptionInApplet() {
        Simulator sim = new Simulator();

        String appletAIDStr = "010203040506070809";
        AID appletAID = AIDUtil.create(appletAIDStr);
        sim.installApplet(appletAID, SymmetricCipherApplet.class);
        try (var instance = sim.connect()) {
            var selectResponse = instance.transmit(AIDUtil.select(appletAID));
            assertEquals(selectResponse.getSW(), 0x9000);

            // 1. Send C-APDU to set AES key
            // Create C-APDU to send 128-bit AES key in CData
            byte[] key = Hex.decode(SymmetricCipherImplTest.AES_CBC_128_TEST[0]);

            // Send C-APDU
            var response = instance.transmit(new CommandAPDU(0x10, 0x10, KeyBuilder.LENGTH_AES_128, 0x00, key));
            // Check command succeeded
            assertEquals(response.getSW(), 0x9000);

            // 2. Send C-APDU to encrypt data with ALG_AES_BLOCK_128_CBC_NOPAD
            // Create C-APDU to send data to encrypt and read the encrypted back
            byte[] data = Hex.decode(SymmetricCipherImplTest.AES_CBC_128_TEST[1]);
            int apdu_Le = data.length;

            // Send C-APDU to encrypt data
            response = instance.transmit(new CommandAPDU(0x10, 0x11, Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, 0x00, data, apdu_Le));
            // Check command succeeded
            assertEquals(response.getSW(), 0x9000);

            var encryptedData = response.getData();

            // Prove that encrypted data is not equal the original one
            assertFalse(Arrays.areEqual(encryptedData, data));

            // 3. Send C-APDU to decrypt data with ALG_AES_BLOCK_128_CBC_NOPAD and read back to check
            // Create C-APDU to decrypt data
            apdu_Le = encryptedData.length;

            // Send C-APDU to encrypt data
            response = instance.transmit(new CommandAPDU(0x10, 0x12, Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, 0x00, encryptedData, apdu_Le));
            // Check command succeeded
            assertEquals(response.getSW(), 0x9000);

            var decryptedData = response.getData();

            // Check decrypted data is equal to the original one
            assertEquals(decryptedData, data);

            // 4. Send C-APDU to encrypt data with ALG_DES_CBC_NOPAD, intend to send mismatched cipher DES algorithm
            data = Hex.decode(SymmetricCipherImplTest.MESSAGE_15);
            apdu_Le = data.length;

            // Send C-APDU to encrypt data
            response = instance.transmit(new CommandAPDU(0x20, 0x11, Cipher.ALG_DES_CBC_NOPAD, 0x00, data, apdu_Le));
            // Check exception for ISO7816.SW_UNKNOWN
            assertEquals(response.getSW(), 0x6F00);

        }
    }

    /**
     * Test DES encryption/decryption and try AES cipher with DES key type
     */
    @Test
    public void testSymmetricCipherDESEncryptionInApplet() {
        Simulator sim = new Simulator();

        String appletAIDStr = "010203040506070809";
        AID appletAID = AIDUtil.create(appletAIDStr);
        sim.installApplet(appletAID, SymmetricCipherApplet.class);

        try (var instance = sim.connect()) {
            var selectResponse = instance.transmit(AIDUtil.select(appletAID));
            assertEquals(selectResponse.getSW(), 0x9000);

            // 1. Send C-APDU to set DES key
            // Create C-APDU to send DES3_3KEY in CData
            byte[] key = Hex.decode(SymmetricCipherImplTest.DES3_KEY);

            // Send C-APDU
            var response = instance.transmit(new CommandAPDU(0x20, 0x10, KeyBuilder.LENGTH_DES3_3KEY, 0x00, key));
            // Check command succeeded
            assertEquals(response.getSW(), 0x9000);

            // 2. Send C-APDU to encrypt data with ALG_DES_CBC_ISO9797_M1
            // Create C-APDU to send data to encrypt and read the encrypted back
            byte[] data = Hex.decode(SymmetricCipherImplTest.MESSAGE_15);
            int apdu_Le = 16;

            // Send C-APDU to encrypt data
            response = instance.transmit(new CommandAPDU(0x20, 0x11, Cipher.ALG_DES_CBC_ISO9797_M1, 0x00, data, apdu_Le));
            // Check command succeeded
            assertEquals(response.getSW(), 0x9000);

            var encryptedData = response.getData();

            // Prove that encrypted data is not equal the original one
            assertFalse(Arrays.areEqual(encryptedData, data));
            // Check that encrypted data is correct
            assertEquals(encryptedData, Hex.decode(SymmetricCipherImplTest.DES3_ENCRYPTED_15[0]));

            // 3. Send C-APDU to decrypt data with ALG_DES_CBC_ISO9797_M1 and read back to check
            // Create C-APDU to decrypt data
            apdu_Le = data.length;

            // Send C-APDU to encrypt data
            response = instance.transmit(new CommandAPDU(0x20, 0x12, Cipher.ALG_DES_CBC_ISO9797_M1, 0x00, encryptedData, apdu_Le));
            // Check command succeeded
            assertEquals(response.getSW(), 0x9000);

            var decryptedData = response.getData();

            // Check decrypted data is equal to the original one
            assertEquals(decryptedData, data);

            // 4. Send C-APDU to encrypt data with ALG_AES_BLOCK_128_CBC_NOPAD, intend to send mismatched cipher AES algorithm
            data = Hex.decode(SymmetricCipherImplTest.AES_CBC_128_TEST[1]);
            apdu_Le = data.length;

            // Send C-APDU to encrypt data
            response = instance.transmit(new CommandAPDU(0x10, 0x11, Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, 0x00, data, apdu_Le));
            // Check exception for ISO7816.SW_UNKNOWN
            assertEquals(response.getSW(), 0x6F00);
        }
    }
}
