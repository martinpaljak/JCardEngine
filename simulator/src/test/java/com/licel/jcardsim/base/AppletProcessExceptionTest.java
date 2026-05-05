// SPDX-FileCopyrightText: 2022 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.samples.RuntimeExceptionApplet;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.*;
import javacard.framework.service.ServiceException;
import javacard.security.CryptoException;
import javacardx.biometry.BioException;
import javacardx.biometry1toN.Bio1toNException;
import javacardx.external.ExternalException;
import javacardx.framework.string.StringException;
import javacardx.framework.tlv.TLVException;
import javacardx.framework.util.UtilException;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.EngineSession;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AppletProcessExceptionTest {
    private static final byte CLA_CRYPTO_EXCEPTION = 1;
    private static final byte CLA_APDU_EXCEPTION = 2;
    private static final byte CLA_SYSTEM_EXCEPTION = 3;
    private static final byte CLA_SERVICE_EXCEPTION = 4;
    private static final byte CLA_BIO_EXCEPTION = 5;
    private static final byte CLA_BIO_1_TO_N_EXCEPTION = 6;
    private static final byte CLA_EXTERNAL_EXCEPTION = 7;
    private static final byte CLA_PIN_EXCEPTION = 8;
    private static final byte CLA_STRING_EXCEPTION = 9;
    private static final byte CLA_TLV_EXCEPTION = 10;
    private static final byte CLA_TRANSACTION_EXCEPTION = 11;
    private static final byte CLA_UTIL_EXCEPTION = 12;
    private static final byte INS_JUST_THROW = 0;
    private static final byte INS_HAS_CATCH_EXCEPTION = 1;

    private static final String appletAIDStr = "010203040506070809";

    @Test
    public void testCryptoException() {
        try (var instance = getReadySimulator()) {

            // Test CryptoException.ILLEGAL_VALUE without try catch
            byte[] apdu = new byte[]{CLA_CRYPTO_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, CryptoException.ILLEGAL_VALUE);
            var responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test CryptoException.ILLEGAL_VALUE with try catch
            apdu = new byte[]{CLA_CRYPTO_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, CryptoException.ILLEGAL_VALUE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test CryptoException.UNINITIALIZED_KEY without try catch
            apdu = new byte[]{CLA_CRYPTO_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, CryptoException.UNINITIALIZED_KEY);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test CryptoException.UNINITIALIZED_KEY with try catch
            apdu = new byte[]{CLA_CRYPTO_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, CryptoException.UNINITIALIZED_KEY);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test CryptoException.NO_SUCH_ALGORITHM without try catch
            apdu = new byte[]{CLA_CRYPTO_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, CryptoException.NO_SUCH_ALGORITHM);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test CryptoException.NO_SUCH_ALGORITHM with try catch
            apdu = new byte[]{CLA_CRYPTO_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, CryptoException.NO_SUCH_ALGORITHM);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test CryptoException.INVALID_INIT without try catch
            apdu = new byte[]{CLA_CRYPTO_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, CryptoException.INVALID_INIT);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test CryptoException.INVALID_INIT with try catch
            apdu = new byte[]{CLA_CRYPTO_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, CryptoException.INVALID_INIT);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test CryptoException.ILLEGAL_USE without try catch
            apdu = new byte[]{CLA_CRYPTO_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, CryptoException.ILLEGAL_USE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test CryptoException.ILLEGAL_USE with try catch
            apdu = new byte[]{CLA_CRYPTO_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, CryptoException.ILLEGAL_USE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());
        }
    }

    @Test
    public void testAPDUException() {
        try (var instance = getReadySimulator()) {

            // Test APDUException.ILLEGAL_USE without try catch
            byte[] apdu = new byte[]{CLA_APDU_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, APDUException.ILLEGAL_USE);
            var responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test APDUException.ILLEGAL_USE with try catch
            apdu = new byte[]{CLA_APDU_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, APDUException.ILLEGAL_USE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test APDUException.BUFFER_BOUNDS without try catch
            apdu = new byte[]{CLA_APDU_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, APDUException.BUFFER_BOUNDS);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test APDUException.BUFFER_BOUNDS with try catch
            apdu = new byte[]{CLA_APDU_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, APDUException.BUFFER_BOUNDS);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test APDUException.BAD_LENGTH without try catch
            apdu = new byte[]{CLA_APDU_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, APDUException.BAD_LENGTH);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test APDUException.BAD_LENGTH with try catch
            apdu = new byte[]{CLA_APDU_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, APDUException.BAD_LENGTH);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test APDUException.IO_ERROR without try catch
            apdu = new byte[]{CLA_APDU_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, APDUException.IO_ERROR);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test APDUException.IO_ERROR with try catch
            apdu = new byte[]{CLA_APDU_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, APDUException.IO_ERROR);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test APDUException.NO_T0_GETRESPONSE without try catch
            apdu = new byte[]{CLA_APDU_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, APDUException.NO_T0_GETRESPONSE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test APDUException.NO_T0_GETRESPONSE with try catch
            apdu = new byte[]{CLA_APDU_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, APDUException.NO_T0_GETRESPONSE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test APDUException.T1_IFD_ABORT without try catch
            apdu = new byte[]{CLA_APDU_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, APDUException.T1_IFD_ABORT);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test APDUException.T1_IFD_ABORT with try catch
            apdu = new byte[]{CLA_APDU_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, APDUException.T1_IFD_ABORT);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test APDUException.NO_T0_REISSUE without try catch
            apdu = new byte[]{CLA_APDU_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, APDUException.NO_T0_REISSUE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test APDUException.NO_T0_REISSUE with try catch
            apdu = new byte[]{CLA_APDU_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, APDUException.NO_T0_REISSUE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());
        }
    }

    @Test
    public void testSystemException() {
        try (var instance = getReadySimulator()) {

            // Test SystemException.ILLEGAL_VALUE without try catch
            byte[] apdu = new byte[]{CLA_SYSTEM_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, SystemException.ILLEGAL_VALUE);
            var responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test SystemException.ILLEGAL_VALUE with try catch
            apdu = new byte[]{CLA_SYSTEM_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, SystemException.ILLEGAL_VALUE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test SystemException.NO_TRANSIENT_SPACE without try catch
            apdu = new byte[]{CLA_SYSTEM_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, SystemException.NO_TRANSIENT_SPACE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test SystemException.NO_TRANSIENT_SPACE with try catch
            apdu = new byte[]{CLA_SYSTEM_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, SystemException.NO_TRANSIENT_SPACE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test SystemException.ILLEGAL_TRANSIENT without try catch
            apdu = new byte[]{CLA_SYSTEM_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, SystemException.ILLEGAL_TRANSIENT);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test SystemException.ILLEGAL_TRANSIENT with try catch
            apdu = new byte[]{CLA_SYSTEM_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, SystemException.ILLEGAL_TRANSIENT);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test SystemException.ILLEGAL_AID without try catch
            apdu = new byte[]{CLA_SYSTEM_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, SystemException.ILLEGAL_AID);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test SystemException.ILLEGAL_AID with try catch
            apdu = new byte[]{CLA_SYSTEM_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, SystemException.ILLEGAL_AID);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test SystemException.NO_RESOURCE without try catch
            apdu = new byte[]{CLA_SYSTEM_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, SystemException.NO_RESOURCE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test SystemException.NO_RESOURCE with try catch
            apdu = new byte[]{CLA_SYSTEM_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, SystemException.NO_RESOURCE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test SystemException.ILLEGAL_USE without try catch
            apdu = new byte[]{CLA_SYSTEM_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, SystemException.ILLEGAL_USE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test SystemException.ILLEGAL_USE with try catch
            apdu = new byte[]{CLA_SYSTEM_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, SystemException.ILLEGAL_USE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());
        }
    }

    @Test
    public void testServiceException() {
        try (var instance = getReadySimulator()) {

            // Test ServiceException.ILLEGAL_PARAM without try catch
            byte[] apdu = new byte[]{CLA_SERVICE_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, ServiceException.ILLEGAL_PARAM);
            var responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test ServiceException.ILLEGAL_PARAM without try catch
            apdu = new byte[]{CLA_SERVICE_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, ServiceException.ILLEGAL_PARAM);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test ServiceException.DISPATCH_TABLE_FULL without try catch
            apdu = new byte[]{CLA_SERVICE_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, ServiceException.DISPATCH_TABLE_FULL);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test ServiceException.DISPATCH_TABLE_FULL with try catch
            apdu = new byte[]{CLA_SERVICE_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, ServiceException.DISPATCH_TABLE_FULL);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test ServiceException.COMMAND_DATA_TOO_LONG without try catch
            apdu = new byte[]{CLA_SERVICE_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, ServiceException.COMMAND_DATA_TOO_LONG);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test ServiceException.COMMAND_DATA_TOO_LONG with try catch
            apdu = new byte[]{CLA_SERVICE_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, ServiceException.COMMAND_DATA_TOO_LONG);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test ServiceException.CANNOT_ACCESS_IN_COMMAND without try catch
            apdu = new byte[]{CLA_SERVICE_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, ServiceException.CANNOT_ACCESS_IN_COMMAND);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test ServiceException.CANNOT_ACCESS_IN_COMMAND with try catch
            apdu = new byte[]{CLA_SERVICE_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, ServiceException.CANNOT_ACCESS_IN_COMMAND);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test ServiceException.CANNOT_ACCESS_OUT_COMMAND without try catch
            apdu = new byte[]{CLA_SERVICE_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, ServiceException.CANNOT_ACCESS_OUT_COMMAND);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test ServiceException.CANNOT_ACCESS_OUT_COMMAND with try catch
            apdu = new byte[]{CLA_SERVICE_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, ServiceException.CANNOT_ACCESS_OUT_COMMAND);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test ServiceException.COMMAND_IS_FINISHED without try catch
            apdu = new byte[]{CLA_SERVICE_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, ServiceException.COMMAND_IS_FINISHED);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test ServiceException.COMMAND_IS_FINISHED with try catch
            apdu = new byte[]{CLA_SERVICE_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, ServiceException.COMMAND_IS_FINISHED);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test ServiceException.REMOTE_OBJECT_NOT_EXPORTED without try catch
            apdu = new byte[]{CLA_SERVICE_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, ServiceException.REMOTE_OBJECT_NOT_EXPORTED);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test ServiceException.REMOTE_OBJECT_NOT_EXPORTED with try catch
            apdu = new byte[]{CLA_SERVICE_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, ServiceException.REMOTE_OBJECT_NOT_EXPORTED);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());
        }
    }

    @Test
    public void testBioException() {
        try (var instance = getReadySimulator()) {

            // Test BioException.ILLEGAL_VALUE without try catch
            byte[] apdu = new byte[]{CLA_BIO_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, BioException.ILLEGAL_VALUE);
            var responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test BioException.ILLEGAL_VALUE without try catch
            apdu = new byte[]{CLA_BIO_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, BioException.ILLEGAL_VALUE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test BioException.INVALID_DATA without try catch
            apdu = new byte[]{CLA_BIO_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, BioException.INVALID_DATA);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test BioException.INVALID_DATA with try catch
            apdu = new byte[]{CLA_BIO_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, BioException.INVALID_DATA);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test BioException.NO_SUCH_BIO_TEMPLATE without try catch
            apdu = new byte[]{CLA_BIO_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, BioException.NO_SUCH_BIO_TEMPLATE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test BioException.NO_SUCH_BIO_TEMPLATE with try catch
            apdu = new byte[]{CLA_BIO_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, BioException.NO_SUCH_BIO_TEMPLATE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test BioException.NO_TEMPLATES_ENROLLED without try catch
            apdu = new byte[]{CLA_BIO_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, BioException.NO_TEMPLATES_ENROLLED);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test BioException.NO_TEMPLATES_ENROLLED with try catch
            apdu = new byte[]{CLA_BIO_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, BioException.NO_TEMPLATES_ENROLLED);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test BioException.ILLEGAL_USE without try catch
            apdu = new byte[]{CLA_BIO_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, BioException.ILLEGAL_USE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test BioException.ILLEGAL_USE with try catch
            apdu = new byte[]{CLA_BIO_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, BioException.ILLEGAL_USE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());
        }
    }

    @Test
    public void testBio1toNException() {
        try (var instance = getReadySimulator()) {

            // Test Bio1toNException.ILLEGAL_VALUE without try catch
            byte[] apdu = new byte[]{CLA_BIO_1_TO_N_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, Bio1toNException.ILLEGAL_VALUE);
            var responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test Bio1toNException.ILLEGAL_VALUE with try catch
            apdu = new byte[]{CLA_BIO_1_TO_N_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, Bio1toNException.ILLEGAL_VALUE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test Bio1toNException.INVALID_DATA without try catch
            apdu = new byte[]{CLA_BIO_1_TO_N_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, Bio1toNException.INVALID_DATA);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test Bio1toNException.INVALID_DATA with try catch
            apdu = new byte[]{CLA_BIO_1_TO_N_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, Bio1toNException.INVALID_DATA);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test Bio1toNException.UNSUPPORTED_BIO_TYPE without try catch
            apdu = new byte[]{CLA_BIO_1_TO_N_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, Bio1toNException.UNSUPPORTED_BIO_TYPE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test Bio1toNException.UNSUPPORTED_BIO_TYPE with try catch
            apdu = new byte[]{CLA_BIO_1_TO_N_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, Bio1toNException.UNSUPPORTED_BIO_TYPE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test Bio1toNException.NO_BIO_TEMPLATE_ENROLLED without try catch
            apdu = new byte[]{CLA_BIO_1_TO_N_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, Bio1toNException.NO_BIO_TEMPLATE_ENROLLED);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test Bio1toNException.NO_BIO_TEMPLATE_ENROLLED with try catch
            apdu = new byte[]{CLA_BIO_1_TO_N_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, Bio1toNException.NO_BIO_TEMPLATE_ENROLLED);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test Bio1toNException.ILLEGAL_USE without try catch
            apdu = new byte[]{CLA_BIO_1_TO_N_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, Bio1toNException.ILLEGAL_USE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test Bio1toNException.ILLEGAL_USE with try catch
            apdu = new byte[]{CLA_BIO_1_TO_N_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, Bio1toNException.ILLEGAL_USE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test Bio1toNException.BIO_TEMPLATE_DATA_CAPACITY_EXCEEDED without try catch
            apdu = new byte[]{CLA_BIO_1_TO_N_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, Bio1toNException.BIO_TEMPLATE_DATA_CAPACITY_EXCEEDED);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test Bio1toNException.BIO_TEMPLATE_DATA_CAPACITY_EXCEEDED with try catch
            apdu = new byte[]{CLA_BIO_1_TO_N_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, Bio1toNException.BIO_TEMPLATE_DATA_CAPACITY_EXCEEDED);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test Bio1toNException.MISMATCHED_BIO_TYPE without try catch
            apdu = new byte[]{CLA_BIO_1_TO_N_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, Bio1toNException.MISMATCHED_BIO_TYPE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test Bio1toNException.MISMATCHED_BIO_TYPE with try catch
            apdu = new byte[]{CLA_BIO_1_TO_N_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, Bio1toNException.MISMATCHED_BIO_TYPE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());
        }
    }

    @Test
    public void testExternalException() {
        try (var instance = getReadySimulator()) {

            // Test ExternalException.NO_SUCH_SUBSYSTEM without try catch
            byte[] apdu = new byte[]{CLA_EXTERNAL_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, ExternalException.NO_SUCH_SUBSYSTEM);
            var responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test ExternalException.NO_SUCH_SUBSYSTEM with try catch
            apdu = new byte[]{CLA_EXTERNAL_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, ExternalException.NO_SUCH_SUBSYSTEM);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test ExternalException.INVALID_PARAM without try catch
            apdu = new byte[]{CLA_EXTERNAL_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, ExternalException.INVALID_PARAM);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test ExternalException.INVALID_PARAM with try catch
            apdu = new byte[]{CLA_EXTERNAL_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, ExternalException.INVALID_PARAM);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test ExternalException.INTERNAL_ERROR without try catch
            apdu = new byte[]{CLA_EXTERNAL_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, ExternalException.INTERNAL_ERROR);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test ExternalException.INTERNAL_ERROR with try catch
            apdu = new byte[]{CLA_EXTERNAL_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, ExternalException.INTERNAL_ERROR);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());
        }
    }

    @Test
    public void testPINException() {
        try (var instance = getReadySimulator()) {

            // Test PINException.ILLEGAL_VALUE without try catch
            byte[] apdu = new byte[]{CLA_PIN_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, PINException.ILLEGAL_VALUE);
            var responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test PINException.ILLEGAL_VALUE with try catch
            apdu = new byte[]{CLA_PIN_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, PINException.ILLEGAL_VALUE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test PINException.ILLEGAL_STATE without try catch
            apdu = new byte[]{CLA_PIN_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, PINException.ILLEGAL_STATE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test PINException.ILLEGAL_STATE with try catch
            apdu = new byte[]{CLA_PIN_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, PINException.ILLEGAL_STATE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());
        }
    }

    @Test
    public void testStringException() {
        try (var instance = getReadySimulator()) {

            // Test StringException.UNSUPPORTED_ENCODING without try catch
            byte[] apdu = new byte[]{CLA_STRING_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, StringException.UNSUPPORTED_ENCODING);
            var responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test StringException.UNSUPPORTED_ENCODING with try catch
            apdu = new byte[]{CLA_STRING_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, StringException.UNSUPPORTED_ENCODING);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test StringException.ILLEGAL_NUMBER_FORMAT without try catch
            apdu = new byte[]{CLA_STRING_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, StringException.ILLEGAL_NUMBER_FORMAT);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test StringException.ILLEGAL_NUMBER_FORMAT with try catch
            apdu = new byte[]{CLA_STRING_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, StringException.ILLEGAL_NUMBER_FORMAT);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test StringException.INVALID_BYTE_SEQUENCE without try catch
            apdu = new byte[]{CLA_STRING_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, StringException.INVALID_BYTE_SEQUENCE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test StringException.INVALID_BYTE_SEQUENCE with try catch
            apdu = new byte[]{CLA_STRING_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, StringException.INVALID_BYTE_SEQUENCE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());
        }
    }

    @Test
    public void testTLVException() {
        try (var instance = getReadySimulator()) {

            // Test TLVException.INVALID_PARAM without try catch
            byte[] apdu = new byte[]{CLA_TLV_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.INVALID_PARAM);
            var responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test TLVException.INVALID_PARAM with try catch
            apdu = new byte[]{CLA_TLV_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.INVALID_PARAM);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test TLVException.ILLEGAL_SIZE without try catch
            apdu = new byte[]{CLA_TLV_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.ILLEGAL_SIZE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test TLVException.ILLEGAL_SIZE with try catch
            apdu = new byte[]{CLA_TLV_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.ILLEGAL_SIZE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test TLVException.EMPTY_TAG without try catch
            apdu = new byte[]{CLA_TLV_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.EMPTY_TAG);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test TLVException.EMPTY_TAG with try catch
            apdu = new byte[]{CLA_TLV_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.EMPTY_TAG);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test TLVException.EMPTY_TLV without try catch
            apdu = new byte[]{CLA_TLV_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.EMPTY_TLV);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test TLVException.EMPTY_TLV with try catch
            apdu = new byte[]{CLA_TLV_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.EMPTY_TLV);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test TLVException.MALFORMED_TAG without try catch
            apdu = new byte[]{CLA_TLV_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.MALFORMED_TAG);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test TLVException.MALFORMED_TAG with try catch
            apdu = new byte[]{CLA_TLV_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.MALFORMED_TAG);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test TLVException.MALFORMED_TLV without try catch
            apdu = new byte[]{CLA_TLV_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.MALFORMED_TLV);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test TLVException.INSUFFICIENT_STORAGE with try catch
            apdu = new byte[]{CLA_TLV_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.INSUFFICIENT_STORAGE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test TLVException.INSUFFICIENT_STORAGE with try catch
            apdu = new byte[]{CLA_TLV_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.INSUFFICIENT_STORAGE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test TLVException.TAG_SIZE_GREATER_THAN_127 with try catch
            apdu = new byte[]{CLA_TLV_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.TAG_SIZE_GREATER_THAN_127);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test TLVException.TAG_SIZE_GREATER_THAN_127 with try catch
            apdu = new byte[]{CLA_TLV_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.TAG_SIZE_GREATER_THAN_127);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test TLVException.TAG_NUMBER_GREATER_THAN_32767 with try catch
            apdu = new byte[]{CLA_TLV_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.TAG_NUMBER_GREATER_THAN_32767);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test TLVException.TAG_NUMBER_GREATER_THAN_32767 with try catch
            apdu = new byte[]{CLA_TLV_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.TAG_NUMBER_GREATER_THAN_32767);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test TLVException.TLV_SIZE_GREATER_THAN_32767 with try catch
            apdu = new byte[]{CLA_TLV_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.TLV_SIZE_GREATER_THAN_32767);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test TLVException.TLV_SIZE_GREATER_THAN_32767 with try catch
            apdu = new byte[]{CLA_TLV_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.TLV_SIZE_GREATER_THAN_32767);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test TLVException.TLV_LENGTH_GREATER_THAN_32767 with try catch
            apdu = new byte[]{CLA_TLV_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.TLV_LENGTH_GREATER_THAN_32767);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test TLVException.TLV_LENGTH_GREATER_THAN_32767 with try catch
            apdu = new byte[]{CLA_TLV_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TLVException.TLV_LENGTH_GREATER_THAN_32767);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());
        }
    }

    @Test
    public void testTransactionException() {
        try (var instance = getReadySimulator()) {

            // Test TransactionException.IN_PROGRESS without try catch
            byte[] apdu = new byte[]{CLA_TRANSACTION_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TransactionException.IN_PROGRESS);
            var responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test TransactionException.IN_PROGRESS with try catch
            apdu = new byte[]{CLA_TRANSACTION_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TransactionException.IN_PROGRESS);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test TransactionException.NOT_IN_PROGRESS without try catch
            apdu = new byte[]{CLA_TRANSACTION_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TransactionException.NOT_IN_PROGRESS);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test TransactionException.NOT_IN_PROGRESS with try catch
            apdu = new byte[]{CLA_TRANSACTION_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TransactionException.NOT_IN_PROGRESS);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test TransactionException.BUFFER_FULL without try catch
            apdu = new byte[]{CLA_TRANSACTION_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TransactionException.BUFFER_FULL);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test TransactionException.BUFFER_FULL with try catch
            apdu = new byte[]{CLA_TRANSACTION_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TransactionException.BUFFER_FULL);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test TransactionException.INTERNAL_FAILURE without try catch
            apdu = new byte[]{CLA_TRANSACTION_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TransactionException.INTERNAL_FAILURE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test TransactionException.INTERNAL_FAILURE with try catch
            apdu = new byte[]{CLA_TRANSACTION_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TransactionException.INTERNAL_FAILURE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test TransactionException.ILLEGAL_USE without try catch
            apdu = new byte[]{CLA_TRANSACTION_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TransactionException.ILLEGAL_USE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test TransactionException.ILLEGAL_USE with try catch
            apdu = new byte[]{CLA_TRANSACTION_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, TransactionException.ILLEGAL_USE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());
        }
    }

    @Test
    public void testUtilException() {
        try (var instance = getReadySimulator()) {

            // Test UtilException.ILLEGAL_VALUE without try catch
            byte[] apdu = new byte[]{CLA_UTIL_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, UtilException.ILLEGAL_VALUE);
            var responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test UtilException.ILLEGAL_VALUE with try catch
            apdu = new byte[]{CLA_UTIL_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, UtilException.ILLEGAL_VALUE);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());

            // Test UtilException.TYPE_MISMATCHED without try catch
            apdu = new byte[]{CLA_UTIL_EXCEPTION, INS_JUST_THROW, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, UtilException.TYPE_MISMATCHED);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_UNKNOWN, responseApdu.getSW());

            // Test UtilException.TYPE_MISMATCHED with try catch
            apdu = new byte[]{CLA_UTIL_EXCEPTION, INS_HAS_CATCH_EXCEPTION, 0, 0};
            Util.setShort(apdu, ISO7816.OFFSET_P1, UtilException.TYPE_MISMATCHED);
            responseApdu = instance.transmit(new CommandAPDU(apdu));
            assertEquals(ISO7816.SW_FUNC_NOT_SUPPORTED, responseApdu.getSW());
        }
    }

    private EngineSession getReadySimulator() {
        Simulator instance = new Simulator();
        AID appletAID = AIDUtil.create(appletAIDStr);

        instance.installApplet(appletAID, RuntimeExceptionApplet.class);
        instance.selectApplet(appletAID);
        return instance.connect();
    }
}
