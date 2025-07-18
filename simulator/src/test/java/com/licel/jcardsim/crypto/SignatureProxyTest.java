/*
 * Copyright 2022 Licel Corporation.
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
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class SignatureProxyTest {

    private static final Logger log = LoggerFactory.getLogger(SignatureProxyTest.class);
    // The deprecated signature algorithm list is created because JavaCard 3.0.5 API uses only javadoc annotation @deprecated
    // And not use the Java annotation @Deprecated, which can be read by java.lang.reflect.Field
    // https://docs.oracle.com/javacard/3.0.5/api/javacard/security/Signature.html
    String[] SIGNATURE_DEPRECATED_ALG_JAVACARD_V3_0_5 = {
            "ALG_AES_MAC_192_NOPAD",
            "ALG_AES_MAC_256_NOPAD",
    };

    @Test
    public void testSupportSignatureForJavaCardv3_0_5() {
        ArrayList<Field> signature_alg_fields = new ArrayList<>();

        for (Field field : Signature.class.getDeclaredFields()) {
            if (field.getName().startsWith("ALG_")) {
                List<String> deprecated_list = Arrays.asList(SIGNATURE_DEPRECATED_ALG_JAVACARD_V3_0_5);
                if (!deprecated_list.contains(field.getName()))
                    signature_alg_fields.add(field);
            }
        }

        for (Field alg_field : signature_alg_fields) {
            try {
                Signature sig = Signature.getInstance(alg_field.getByte(null), false);
            } catch (CryptoException ex) {
                if (ex.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                    log.warn("Implemented: getInstance({})", alg_field.getName());
                } else {
                    log.error("Invalid implementation: {}", alg_field.getName());
                }
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        }

        for (Field md : Arrays.stream(MessageDigest.class.getDeclaredFields()).filter(n -> n.getName().startsWith("ALG_")).collect(Collectors.toList())) {
            for (Field ca : Arrays.stream(Signature.class.getDeclaredFields()).filter(n -> n.getName().startsWith("SIG_CIPHER_")).collect(Collectors.toList())) {
                for (Field pad : Arrays.stream(Cipher.class.getDeclaredFields()).filter(n -> n.getName().startsWith("PAD_")).collect(Collectors.toList())) {
                    try {
                        Signature sig = Signature.getInstance(md.getByte(null), ca.getByte(null), pad.getByte(null), false);
                        log.info("Implemented: getInstance({}, {}, {})", md.getName(), ca.getName(), pad.getName());
                    } catch (CryptoException e) {
                        if (e.getReason() != CryptoException.NO_SUCH_ALGORITHM) {
                            log.error("Invalid implementation: {}, {}, {}", md.getName(), ca.getName(), pad.getName());
                        }
                        // No point in spamming the log.
                    } catch (IllegalAccessException e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        }
    }
}
