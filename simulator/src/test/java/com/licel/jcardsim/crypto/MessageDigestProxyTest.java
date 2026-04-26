// SPDX-FileCopyrightText: 2022 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.MessageDigest;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.ArrayList;

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
}
