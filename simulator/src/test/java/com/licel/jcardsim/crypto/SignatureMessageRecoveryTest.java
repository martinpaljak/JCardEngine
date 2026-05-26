// SPDX-FileCopyrightText: 2014 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.framework.JCSystem;
import javacard.security.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.bouncycastle.util.encoders.Hex;

/**
 * SignatureMessageRecovery Test
 * based on JCDK Sample
 */
public class SignatureMessageRecoveryTest extends SimulatorCoreTest {

    //--RSA Keypair data
    private static final byte[] RSA_PUB_KEY_EXP = {(byte) 0x01, (byte) 0x00, (byte) 0x01};
    private static final byte[] RSA_PUB_PRIV_KEY_MOD = Hex.decode("bedfd37a08e29a5827542a4918cee41a60dc6275bdb08d15a365e67ba9dc09115f9fbf29e6c282c8356b0f109b1962fdbd964921e4220808806cd1dea6d3c38f");
    private static final byte[] RSA_PRIV_KEY_EXP = Hex.decode("8421fe0ba4caf97dbcfc0ea9bb7abd7d65402b08c6dfc94b096a293bc242882344af08824cff42a4b8d2dacceec534ed7101ab3b76de6ca2cb7c38b69a4b2801");

    static RSAPublicKey pubKey;
    static RSAPrivateKey privKey;
    static SignatureMessageRecovery sig;
    static KeyPair selfTestKeys;

    /**
     * Only this class's install method should create the applet object.
     */
    @BeforeAll
    static void setUp() {
        pubKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
        privKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
        privKey.setExponent(RSA_PRIV_KEY_EXP, (short) 0, (short) RSA_PRIV_KEY_EXP.length);
        privKey.setModulus(RSA_PUB_PRIV_KEY_MOD, (short) 0, (short) RSA_PUB_PRIV_KEY_MOD.length);
        pubKey.setExponent(RSA_PUB_KEY_EXP, (short) 0, (short) RSA_PUB_KEY_EXP.length);
        pubKey.setModulus(RSA_PUB_PRIV_KEY_MOD, (short) 0, (short) RSA_PUB_PRIV_KEY_MOD.length);
        sig = (SignatureMessageRecovery) Signature.getInstance(Signature.ALG_RSA_SHA_ISO9796_MR, false);
        selfTestKeys = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
        selfTestKeys.genKeyPair();
    }


    /**
     *
     */
    @Test
    public void testCryptoSignAndVerifyFullMsgRecovery() {
        byte[] buffer = new byte[1];

        sig.init(pubKey, Signature.MODE_VERIFY);
        byte[] etalonSign = Hex.decode("a3491d5155054971badc7722ce9a5171f8b1888d5505d52baef6b704d91d093517ec7311d57ffdebb3d99845f78ab6722144a132b3a1ce72c56dccee18642e76");

        short m1Length = sig.beginVerify(etalonSign, (short) 0, (short) etalonSign.length);
        boolean verified = sig.verify(buffer, (short) 0, (short) 0);

        assertEquals(m1Length, 1);

        assertEquals(true, verified);

    }

    @Test
    public void testSelfCryptoSignAndVerifyFullMsgRecovery() {
        byte[] data = new byte[41];
        for (byte i = 0; i < data.length; i++) {
            data[i] = i;
        }
        short[] m1Data = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        byte[] signature = new byte[(short) 256];

        sig.init(selfTestKeys.getPrivate(), Signature.MODE_SIGN);
        short sigLen = sig.sign(data, (short) 0, (short) data.length, signature, (short) 0, m1Data, (short) 0);

        sig.init(selfTestKeys.getPublic(), Signature.MODE_VERIFY);
        short m1Length = sig.beginVerify(signature, (short) 0, sigLen);

        boolean verified = sig.verify(data, (short) 0, (short) 0);

        assertEquals(m1Length, m1Data[0]);

        assertEquals(true, verified);

    }

    @Test
    public void testCryptoVerifyPartMsgRecovery() {
        byte[] data = new byte[70];
        for (byte i = 0; i < data.length; i++) {
            data[i] = i;
        }

        byte[] etalonSign = Hex.decode("2d157989ba716d316c0e2955c00e80c35ca3e8a11265e36fb251447d304a24cfa11baa3048d3704a0be79a051f5f87c78fe4aebcde0a636a284852c0e7d27ffe");

        //recover the recoverable message from signature
        sig.init(pubKey, Signature.MODE_VERIFY);
        short m1Length = sig.beginVerify(etalonSign, (short) 0, (short) etalonSign.length);

        assertEquals(m1Length, 42);


        byte[] etalonNonRecMsg = Hex.decode("2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546");

        boolean verified = sig.verify(etalonNonRecMsg, (short) 0, (short) etalonNonRecMsg.length);
        assertEquals(true, verified);

    }

    @Test
    public void testSelfCryptoSignAndVerifyPartMsgRecovery() {
        byte[] data = new byte[(short) 256];
        for (short i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }
        short[] m1Data = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        byte[] signature = new byte[(short) 256];

        sig.init(selfTestKeys.getPrivate(), Signature.MODE_SIGN);
        short sigLen = sig.sign(data, (short) 0, (short) data.length, signature, (short) 0, m1Data, (short) 0);

        sig.init(selfTestKeys.getPublic(), Signature.MODE_VERIFY);
        short m1Length = sig.beginVerify(signature, (short) 0, sigLen);

        boolean verified = sig.verify(data, m1Length, (short) (data.length - m1Length));

        assertEquals(m1Length, m1Data[0]);

        assertEquals(true, verified);

    }
}
