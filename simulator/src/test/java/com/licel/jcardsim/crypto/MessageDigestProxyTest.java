// SPDX-FileCopyrightText: 2022 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.MessageDigest;
import org.bouncycastle.util.encoders.Hex;
import org.testng.annotations.Test;

import java.lang.reflect.Field;
import java.util.ArrayList;

import static org.testng.Assert.*;

public class MessageDigestProxyTest {

    @Test
    public void testSupportMessageDigestForJavaCardv3_0_5() throws ClassNotFoundException {

        ArrayList<Field> md_alg_fields = new ArrayList<>();

        for (Field field : Class.forName("javacard.security.MessageDigest").getDeclaredFields()) {
            if (field.getName().startsWith("ALG_")) {
                md_alg_fields.add(field);
            }
        }

        for (Field alg_field : md_alg_fields) {
            try {
                MessageDigest md = MessageDigest.getInstance(alg_field.getByte(null), false);
            } catch (Throwable ex) {
                System.out.println("Message Digest algorithm " + alg_field.getName() + " has not been implemented yet!!!");
            }
        }

    }

    @Test
    public void testOneShot() {
        byte[] msg = Hex.decode("616263");
        byte[] digest = new byte[MessageDigest.LENGTH_SHA_256];

        MessageDigest.OneShot md = MessageDigest.OneShot.open(MessageDigest.ALG_SHA_256);
        try {
            // FIPS 180-4 SHA-256("abc")
            assertEquals(md.doFinal(msg, (short) 0, (short) msg.length, digest, (short) 0), MessageDigest.LENGTH_SHA_256);
            assertEquals(digest, Hex.decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
            // multi-part update is not supported on OneShot
            CryptoException u = expectThrows(CryptoException.class, () -> md.update(msg, (short) 0, (short) msg.length));
            assertEquals(u.getReason(), CryptoException.ILLEGAL_USE);
        } finally {
            md.close();
        }
        // after close(), a further call throws ILLEGAL_USE
        CryptoException e = expectThrows(CryptoException.class, () -> md.doFinal(msg, (short) 0, (short) msg.length, digest, (short) 0));
        assertEquals(e.getReason(), CryptoException.ILLEGAL_USE);
    }
}
