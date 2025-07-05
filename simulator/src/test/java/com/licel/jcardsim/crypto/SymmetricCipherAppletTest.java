package com.licel.jcardsim.crypto;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.samples.SymmetricCipherApplet;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.EngineSession;

import static org.junit.jupiter.api.Assertions.*;

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
        sim.selectApplet(appletAID);
        try (EngineSession instance = sim.connect()) {

            // 1. Send C-APDU to set AES key
            // Create C-APDU to send 128-bit AES key in CData
            byte[] key = Hex.decode(SymmetricCipherImplTest.AES_CBC_128_TEST[0]);
            short keyLen = KeyBuilder.LENGTH_AES_128 / 8;
            byte[] commandAPDUHeaderWithLc = new byte[]{0x10, 0x10, (byte) KeyBuilder.LENGTH_AES_128, 0, (byte) keyLen};
            byte[] sendAPDU = new byte[5 + keyLen];
            System.arraycopy(commandAPDUHeaderWithLc, 0, sendAPDU, 0, 5);
            System.arraycopy(key, 0, sendAPDU, 5, keyLen);

            // Send C-APDU
            byte[] response = instance.transmitCommand(sendAPDU);
            // Check command succeeded
            assertEquals(ISO7816.SW_NO_ERROR, Util.getShort(response, (short) 0));

            // 2. Send C-APDU to encrypt data with ALG_AES_BLOCK_128_CBC_NOPAD
            // Create C-APDU to send data to encrypt and read the encrypted back
            byte[] data = Hex.decode(SymmetricCipherImplTest.AES_CBC_128_TEST[1]);
            byte apdu_Lc = (byte) data.length;

            commandAPDUHeaderWithLc = new byte[]{0x10, 0x11, Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, 0, apdu_Lc};
            sendAPDU = new byte[5 + apdu_Lc + 1];
            System.arraycopy(commandAPDUHeaderWithLc, 0, sendAPDU, 0, 5);
            System.arraycopy(data, 0, sendAPDU, 5, apdu_Lc);

            // Set Le
            byte apdu_Le = (byte) data.length;
            sendAPDU[5 + apdu_Lc] = apdu_Le;

            // Send C-APDU to encrypt data
            response = instance.transmitCommand(sendAPDU);
            // Check command succeeded
            assertEquals(ISO7816.SW_NO_ERROR, Util.getShort(response, apdu_Le));

            byte[] encryptedData = new byte[apdu_Le];
            System.arraycopy(response, 0, encryptedData, 0, encryptedData.length);

            // Prove that encrypted data is not equal the original one
            assertFalse(Arrays.areEqual(encryptedData, data));

            // 3. Send C-APDU to decrypt data with ALG_AES_BLOCK_128_CBC_NOPAD and read back to check
            // Create C-APDU to decrypt data
            apdu_Lc = (byte) encryptedData.length;
            commandAPDUHeaderWithLc = new byte[]{0x10, 0x12, Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, 0, apdu_Lc};
            sendAPDU = new byte[5 + apdu_Lc + 1];
            System.arraycopy(commandAPDUHeaderWithLc, 0, sendAPDU, 0, 5);
            System.arraycopy(encryptedData, 0, sendAPDU, 5, apdu_Lc);

            // Set Le
            apdu_Le = (byte) encryptedData.length;
            sendAPDU[5 + apdu_Lc] = apdu_Le;

            // Send C-APDU to encrypt data
            response = instance.transmitCommand(sendAPDU);
            // Check command succeeded
            assertEquals(ISO7816.SW_NO_ERROR, Util.getShort(response, apdu_Le));

            byte[] decryptedData = new byte[apdu_Le];
            System.arraycopy(response, 0, decryptedData, 0, decryptedData.length);

            // Check decrypted data is equal to the original one
            assertTrue(Arrays.areEqual(decryptedData, data));

            // 4. Send C-APDU to encrypt data with ALG_DES_CBC_NOPAD, intend to send mismatched cipher DES algorithm
            data = Hex.decode(SymmetricCipherImplTest.MESSAGE_15);
            apdu_Lc = (byte) data.length;

            commandAPDUHeaderWithLc = new byte[]{0x20, 0x11, Cipher.ALG_DES_CBC_NOPAD, 0, apdu_Lc};
            sendAPDU = new byte[5 + apdu_Lc + 1];
            System.arraycopy(commandAPDUHeaderWithLc, 0, sendAPDU, 0, 5);
            System.arraycopy(data, 0, sendAPDU, 5, apdu_Lc);

            // Set Le
            apdu_Le = (byte) data.length;
            sendAPDU[5 + apdu_Lc] = apdu_Le;

            // Send C-APDU to encrypt data
            response = instance.transmitCommand(sendAPDU);
            // Check exception for ISO7816.SW_UNKNOWN
            assertEquals(ISO7816.SW_UNKNOWN, Util.getShort(response, (short) 0));

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
        sim.selectApplet(appletAID);

        try (EngineSession instance = sim.connect()) {
            // 1. Send C-APDU to set DES key
            // Create C-APDU to send DES3_3KEY in CData
            byte[] key = Hex.decode(SymmetricCipherImplTest.DES3_KEY);
            short keyLen = (short) key.length;
            byte[] commandAPDUHeaderWithLc = new byte[]{0x20, 0x10, (byte) KeyBuilder.LENGTH_DES3_3KEY, 0, (byte) keyLen};
            byte[] sendAPDU = new byte[5 + keyLen];
            System.arraycopy(commandAPDUHeaderWithLc, 0, sendAPDU, 0, 5);
            System.arraycopy(key, 0, sendAPDU, 5, keyLen);

            // Send C-APDU
            byte[] response = instance.transmitCommand(sendAPDU);
            // Check command succeeded
            assertEquals(ISO7816.SW_NO_ERROR, Util.getShort(response, (short) 0));

            // 2. Send C-APDU to encrypt data with ALG_DES_CBC_ISO9797_M1
            // Create C-APDU to send data to encrypt and read the encrypted back
            byte[] data = Hex.decode(SymmetricCipherImplTest.MESSAGE_15);
            byte apdu_Lc = (byte) data.length;

            commandAPDUHeaderWithLc = new byte[]{0x20, 0x11, Cipher.ALG_DES_CBC_ISO9797_M1, 0, apdu_Lc};
            sendAPDU = new byte[5 + apdu_Lc + 1];
            System.arraycopy(commandAPDUHeaderWithLc, 0, sendAPDU, 0, 5);
            System.arraycopy(data, 0, sendAPDU, 5, apdu_Lc);

            // Set Le
            byte apdu_Le = 16;
            sendAPDU[5 + apdu_Lc] = apdu_Le;

            // Send C-APDU to encrypt data
            response = instance.transmitCommand(sendAPDU);
            // Check command succeeded
            assertEquals(ISO7816.SW_NO_ERROR, Util.getShort(response, apdu_Le));

            byte[] encryptedData = new byte[apdu_Le];
            System.arraycopy(response, 0, encryptedData, 0, encryptedData.length);

            // Prove that encrypted data is not equal the original one
            assertFalse(Arrays.areEqual(encryptedData, data));
            // Check that encrypted data is correct
            assertTrue(Arrays.areEqual(encryptedData, Hex.decode(SymmetricCipherImplTest.DES3_ENCRYPTED_15[0])));

            // 3. Send C-APDU to decrypt data with ALG_DES_CBC_ISO9797_M1 and read back to check
            // Create C-APDU to decrypt data
            apdu_Lc = (byte) encryptedData.length;
            commandAPDUHeaderWithLc = new byte[]{0x20, 0x12, Cipher.ALG_DES_CBC_ISO9797_M1, 0, apdu_Lc};
            sendAPDU = new byte[5 + apdu_Lc + 1];
            System.arraycopy(commandAPDUHeaderWithLc, 0, sendAPDU, 0, 5);
            System.arraycopy(encryptedData, 0, sendAPDU, 5, apdu_Lc);

            // Set Le
            apdu_Le = (byte) data.length;
            sendAPDU[5 + apdu_Lc] = apdu_Le;

            // Send C-APDU to encrypt data
            response = instance.transmitCommand(sendAPDU);
            // Check command succeeded
            assertEquals(ISO7816.SW_NO_ERROR, Util.getShort(response, apdu_Le));

            byte[] decryptedData = new byte[apdu_Le];
            System.arraycopy(response, 0, decryptedData, 0, decryptedData.length);

            // Check decrypted data is equal to the original one
            assertTrue(Arrays.areEqual(decryptedData, data));

            // 4. Send C-APDU to encrypt data with ALG_AES_BLOCK_128_CBC_NOPAD, intend to send mismatched cipher AES algorithm
            data = Hex.decode(SymmetricCipherImplTest.AES_CBC_128_TEST[1]);
            apdu_Lc = (byte) data.length;

            commandAPDUHeaderWithLc = new byte[]{0x10, 0x11, Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, 0, apdu_Lc};
            sendAPDU = new byte[5 + apdu_Lc + 1];
            System.arraycopy(commandAPDUHeaderWithLc, 0, sendAPDU, 0, 5);
            System.arraycopy(data, 0, sendAPDU, 5, apdu_Lc);

            // Set Le
            apdu_Le = (byte) data.length;
            sendAPDU[5 + apdu_Lc] = apdu_Le;

            // Send C-APDU to encrypt data
            response = instance.transmitCommand(sendAPDU);
            // Check exception for ISO7816.SW_UNKNOWN
            assertEquals(ISO7816.SW_UNKNOWN, Util.getShort(response, (short) 0));
        }
    }
}
