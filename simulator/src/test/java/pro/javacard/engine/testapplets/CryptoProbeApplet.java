// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.testapplets;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;

// Remote crypto probe. The host sends a raw ALG_*/TYPE_* constant byte, all key components, and
// all inputs; the applet runs one JavaCard crypto call per command. Transport SW is always 9000.
// Response body: byte[0] = 0x00 SUCCESS with operation output in byte[1..], or byte[0] = 0x01
// EXCEPTION with byte[1] = type id and byte[2..3] = reason code big-endian (getReason() for
// CardRuntimeException subclasses, else 0). Slot/length ISOExceptions are thrown before the try
// block and set the transport SW instead.
public class CryptoProbeApplet extends Applet implements ExtendedLength {

    private static final byte INS_NEW_KEY        = (byte) 0x10;
    private static final byte INS_NEW_KEY_SHARED = (byte) 0x11;
    private static final byte INS_SET_COMPONENT  = (byte) 0x20;
    private static final byte INS_GET_COMPONENT  = (byte) 0x21;
    private static final byte INS_GEN_KEYPAIR    = (byte) 0x30;
    private static final byte INS_DIGEST         = (byte) 0x40;
    private static final byte INS_CIPHER         = (byte) 0x50;
    private static final byte INS_SIGN           = (byte) 0x60;
    private static final byte INS_VERIFY         = (byte) 0x61;
    private static final byte INS_KEYAGREEMENT   = (byte) 0x70;
    private static final byte INS_MEMORY         = (byte) 0x80;

    private static final byte P1_MEM_QUERY = (byte) 0x00;
    private static final byte P1_MEM_GC    = (byte) 0x01;

    private static final byte COMP_A           = 1;
    private static final byte COMP_B           = 2;
    private static final byte COMP_G           = 3;
    private static final byte COMP_R           = 4;
    private static final byte COMP_FIELD_FP    = 5;
    private static final byte COMP_K           = 6;
    private static final byte COMP_S           = 7;
    private static final byte COMP_W           = 8;
    private static final byte COMP_SYMMETRIC   = 9;
    private static final byte COMP_RSA_MOD     = 10;
    private static final byte COMP_RSA_EXP     = 11;
    private static final byte COMP_RSA_PRIVEXP = 12;
    private static final byte COMP_P           = 13;
    private static final byte COMP_Q           = 14;
    private static final byte COMP_DP          = 15;
    private static final byte COMP_DQ          = 16;
    private static final byte COMP_PQ          = 17;

    private static final byte OUTCOME_SUCCESS   = (byte) 0x00;
    private static final byte OUTCOME_EXCEPTION = (byte) 0x01;

    // Exception type ids carried in byte[1] of an EXCEPTION outcome.
    private static final byte T_CRYPTO       = 1;
    private static final byte T_SYSTEM       = 2;
    private static final byte T_APDU         = 3;
    private static final byte T_ISO          = 4;
    private static final byte T_PIN          = 5;
    private static final byte T_TRANSACTION  = 6;
    private static final byte T_USER         = 8;
    private static final byte T_CARD_RUNTIME = 9;
    private static final byte T_ARITHMETIC   = 20;
    private static final byte T_AIOOBE       = 21;
    private static final byte T_NPE          = 22;
    private static final byte T_CLASS_CAST   = 23;
    private static final byte T_NEG_ARRAY    = 24;
    private static final byte T_ARRAY_STORE  = 25;
    private static final byte T_IOOBE        = 26;
    private static final byte T_OTHER        = 30;

    private static final short WORK_SIZE = 600;

    // Transient object slots; cleared on reset, which allows the GC to reclaim old key objects.
    private final Object[] slots;
    // Incoming command data, kept off the APDU buffer so extended-length payloads can be assembled.
    private final byte[] work;
    // Outgoing results kept separate from work so crypto calls never share source and destination.
    private final byte[] out;
    // Two-element buffer for the 32-bit JCSystem.getAvailableMemory readings.
    private final short[] memScratch;

    private CryptoProbeApplet() {
        slots = JCSystem.makeTransientObjectArray((short) 8, JCSystem.CLEAR_ON_RESET);
        work = JCSystem.makeTransientByteArray(WORK_SIZE, JCSystem.CLEAR_ON_RESET);
        out = JCSystem.makeTransientByteArray(WORK_SIZE, JCSystem.CLEAR_ON_RESET);
        memScratch = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_RESET);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CryptoProbeApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

        if (JCSystem.isObjectDeletionSupported()) {
            try {
                JCSystem.requestObjectDeletion();
            } catch (SystemException e) {
                // best-effort; a refusal here must not abort the command being processed
            }
        }

        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];
        short dataLen = readIncoming(apdu);

        short outLen;
        switch (ins) {
            case INS_NEW_KEY:
                outLen = doNewKey(p1, dataLen);
                break;
            case INS_NEW_KEY_SHARED:
                outLen = doNewKeyShared(p1, p2, dataLen);
                break;
            case INS_SET_COMPONENT:
                outLen = doSetComponent(p1, p2, dataLen);
                break;
            case INS_GET_COMPONENT:
                outLen = doGetComponent(p1, p2);
                break;
            case INS_GEN_KEYPAIR:
                outLen = doGenKeyPair(p1, p2);
                break;
            case INS_DIGEST:
                outLen = doDigest(p1, dataLen);
                break;
            case INS_CIPHER:
                outLen = doCipher(p1, p2, dataLen);
                break;
            case INS_SIGN:
                outLen = doSign(p1, p2, dataLen);
                break;
            case INS_VERIFY:
                outLen = doVerify(p1, p2, dataLen);
                break;
            case INS_KEYAGREEMENT:
                outLen = doKeyAgreement(p1, p2, dataLen);
                break;
            case INS_MEMORY:
                outLen = doMemory(p1);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                return;
        }
        sendOutgoing(apdu, outLen);
    }

    // Copies the incoming command body into work[0..] and returns its length. Loops over
    // receiveBytes to handle extended-length payloads that exceed the APDU buffer.
    private short readIncoming(APDU apdu) {
        // getIncomingLength() is reliable only after setIncomingAndReceive()
        short received = apdu.setIncomingAndReceive();
        short total = apdu.getIncomingLength();
        if (total == 0) {
            return 0;
        }
        if (total > WORK_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        byte[] buffer = apdu.getBuffer();
        short cdata = apdu.getOffsetCdata();
        short off = 0;
        while (off < total) {
            Util.arrayCopyNonAtomic(buffer, cdata, work, off, received);
            off += received;
            if (off >= total) {
                break;
            }
            received = apdu.receiveBytes(cdata);
        }
        return total;
    }

    // Sends out[0..outLen] via sendBytesLong so outputs longer than the APDU buffer are delivered.
    private void sendOutgoing(APDU apdu, short outLen) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(outLen);
        apdu.sendBytesLong(out, (short) 0, outLen);
    }

    // 0x10 NEW_KEY: data = memType(1), keyConst(1), len(2 BE). memType 0x00 calls
    // buildKey(TYPE, len); any other value calls buildKey(ALG_TYPE, MEMORY_TYPE, len).
    private short doNewKey(byte slot, short dataLen) {
        checkSlot(slot);
        byte memType = work[0];
        byte keyConst = work[1];
        short len = Util.getShort(work, (short) 2);
        try {
            Key key;
            if (memType == 0x00) {
                key = KeyBuilder.buildKey(keyConst, len, false);
            } else {
                key = KeyBuilder.buildKey(keyConst, memType, len, false);
            }
            slots[slot] = key;
            return success((short) 0, false);
        } catch (Throwable t) {
            return fail(t);
        }
    }

    // 0x11 NEW_KEY_SHARED: data = algType(1); shares the domain of the key in domainSlot.
    private short doNewKeyShared(byte slot, byte domainSlot, short dataLen) {
        checkSlot(slot);
        checkSlot(domainSlot);
        byte algType = work[0];
        try {
            Key domain = (Key) slots[domainSlot];
            Key key = KeyBuilder.buildKeyWithSharedDomain(algType, JCSystem.MEMORY_TYPE_PERSISTENT, domain, false);
            slots[slot] = key;
            return success((short) 0, false);
        } catch (Throwable t) {
            return fail(t);
        }
    }

    // 0x20 SET_COMPONENT: command body is the component value. Symmetric/RSA families also
    // dispatch on the stored key's getType().
    private short doSetComponent(byte slot, byte compId, short dataLen) {
        checkSlot(slot);
        try {
            Key key = (Key) slots[slot];
            switch (compId) {
                case COMP_A:
                    ((ECKey) key).setA(work, (short) 0, dataLen);
                    break;
                case COMP_B:
                    ((ECKey) key).setB(work, (short) 0, dataLen);
                    break;
                case COMP_G:
                    ((ECKey) key).setG(work, (short) 0, dataLen);
                    break;
                case COMP_R:
                    ((ECKey) key).setR(work, (short) 0, dataLen);
                    break;
                case COMP_FIELD_FP:
                    ((ECKey) key).setFieldFP(work, (short) 0, dataLen);
                    break;
                case COMP_K:
                    ((ECKey) key).setK(Util.getShort(work, (short) 0));
                    break;
                case COMP_S:
                    ((ECPrivateKey) key).setS(work, (short) 0, dataLen);
                    break;
                case COMP_W:
                    ((ECPublicKey) key).setW(work, (short) 0, dataLen);
                    break;
                case COMP_SYMMETRIC:
                    setSymmetricKey(key, dataLen);
                    break;
                case COMP_RSA_MOD:
                    setModulus(key, dataLen);
                    break;
                case COMP_RSA_EXP:
                    ((RSAPublicKey) key).setExponent(work, (short) 0, dataLen);
                    break;
                case COMP_RSA_PRIVEXP:
                    ((RSAPrivateKey) key).setExponent(work, (short) 0, dataLen);
                    break;
                case COMP_P:
                    ((RSAPrivateCrtKey) key).setP(work, (short) 0, dataLen);
                    break;
                case COMP_Q:
                    ((RSAPrivateCrtKey) key).setQ(work, (short) 0, dataLen);
                    break;
                case COMP_DP:
                    ((RSAPrivateCrtKey) key).setDP1(work, (short) 0, dataLen);
                    break;
                case COMP_DQ:
                    ((RSAPrivateCrtKey) key).setDQ1(work, (short) 0, dataLen);
                    break;
                case COMP_PQ:
                    ((RSAPrivateCrtKey) key).setPQ(work, (short) 0, dataLen);
                    break;
                default:
                    CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            }
            return success((short) 0, false);
        } catch (Throwable t) {
            return fail(t);
        }
    }

    // 0x21 GET_COMPONENT: writes the component into out[3..]; retCode = getter's returned length.
    // Modulus and symmetric key getters also dispatch on getType().
    private short doGetComponent(byte slot, byte compId) {
        checkSlot(slot);
        try {
            Key key = (Key) slots[slot];
            short n;
            switch (compId) {
                case COMP_A:
                    n = ((ECKey) key).getA(out, (short) 3);
                    break;
                case COMP_B:
                    n = ((ECKey) key).getB(out, (short) 3);
                    break;
                case COMP_G:
                    n = ((ECKey) key).getG(out, (short) 3);
                    break;
                case COMP_R:
                    n = ((ECKey) key).getR(out, (short) 3);
                    break;
                case COMP_FIELD_FP:
                    n = ((ECKey) key).getField(out, (short) 3);
                    break;
                case COMP_K:
                    Util.setShort(out, (short) 3, ((ECKey) key).getK());
                    n = 2;
                    break;
                case COMP_S:
                    n = ((ECPrivateKey) key).getS(out, (short) 3);
                    break;
                case COMP_W:
                    n = ((ECPublicKey) key).getW(out, (short) 3);
                    break;
                case COMP_SYMMETRIC:
                    n = getSymmetricKey(key);
                    break;
                case COMP_RSA_MOD:
                    n = getModulus(key);
                    break;
                case COMP_RSA_EXP:
                    n = ((RSAPublicKey) key).getExponent(out, (short) 3);
                    break;
                case COMP_RSA_PRIVEXP:
                    n = ((RSAPrivateKey) key).getExponent(out, (short) 3);
                    break;
                case COMP_P:
                    n = ((RSAPrivateCrtKey) key).getP(out, (short) 3);
                    break;
                case COMP_Q:
                    n = ((RSAPrivateCrtKey) key).getQ(out, (short) 3);
                    break;
                case COMP_DP:
                    n = ((RSAPrivateCrtKey) key).getDP1(out, (short) 3);
                    break;
                case COMP_DQ:
                    n = ((RSAPrivateCrtKey) key).getDQ1(out, (short) 3);
                    break;
                case COMP_PQ:
                    n = ((RSAPrivateCrtKey) key).getPQ(out, (short) 3);
                    break;
                default:
                    CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
                    n = 0;
            }
            return success(n, true);
        } catch (Throwable t) {
            return fail(t);
        }
    }

    // 0x30 GEN_KEYPAIR: generates into the existing public/private key objects in the given slots.
    private short doGenKeyPair(byte pubSlot, byte privSlot) {
        checkSlot(pubSlot);
        checkSlot(privSlot);
        try {
            PublicKey pub = (PublicKey) slots[pubSlot];
            PrivateKey priv = (PrivateKey) slots[privSlot];
            KeyPair kp = new KeyPair(pub, priv);
            kp.genKeyPair();
            return success((short) 0, false);
        } catch (Throwable t) {
            return fail(t);
        }
    }

    // 0x40 DIGEST: P1 = algorithm; command body = input; retCode = digest length.
    private short doDigest(byte alg, short dataLen) {
        try {
            MessageDigest md = MessageDigest.getInstance(alg, false);
            short n = md.doFinal(work, (short) 0, dataLen, out, (short) 3);
            return success(n, true);
        } catch (Throwable t) {
            return fail(t);
        }
    }

    // 0x50 CIPHER: P1 = alg, P2 = mode (0x01 encrypt, else decrypt).
    // data = keySlot(1), ivLen(1), iv(ivLen), input(rest); retCode = doFinal() return value.
    private short doCipher(byte alg, byte mode, short dataLen) {
        try {
            byte keySlot = work[0];
            checkSlot(keySlot);
            short ivLen = (short) (work[1] & 0xFF);
            short ivOff = 2;
            short inOff = (short) (ivOff + ivLen);
            if (inOff > dataLen) {
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            }
            short inLen = (short) (dataLen - inOff);
            Key key = (Key) slots[keySlot];
            byte cipherMode = mode == 0x01 ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT;
            Cipher cipher = Cipher.getInstance(alg, false);
            if (ivLen > 0) {
                cipher.init(key, cipherMode, work, ivOff, ivLen);
            } else {
                cipher.init(key, cipherMode);
            }
            short n = cipher.doFinal(work, inOff, inLen, out, (short) 3);
            return success(n, true);
        } catch (Throwable t) {
            return fail(t);
        }
    }

    // 0x60 SIGN: P1 = alg, P2 = keySlot; command body = message; retCode = sig length.
    private short doSign(byte alg, byte keySlot, short dataLen) {
        checkSlot(keySlot);
        try {
            Key key = (Key) slots[keySlot];
            Signature sig = Signature.getInstance(alg, false);
            sig.init(key, Signature.MODE_SIGN);
            short n = sig.sign(work, (short) 0, dataLen, out, (short) 3);
            return success(n, true);
        } catch (Throwable t) {
            return fail(t);
        }
    }

    // 0x61 VERIFY: P1 = alg, P2 = keySlot; data = sigLen(2 BE), sig(sigLen), message(rest).
    // retCode = verify() result as 1/0; no output bytes.
    private short doVerify(byte alg, byte keySlot, short dataLen) {
        checkSlot(keySlot);
        try {
            short sigLen = Util.getShort(work, (short) 0);
            short sigOff = 2;
            short msgOff = (short) (sigOff + sigLen);
            if (msgOff > dataLen) {
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            }
            short msgLen = (short) (dataLen - msgOff);
            Key key = (Key) slots[keySlot];
            Signature sig = Signature.getInstance(alg, false);
            sig.init(key, Signature.MODE_VERIFY);
            boolean ok = sig.verify(work, msgOff, msgLen, work, sigOff, sigLen);
            return success(ok ? (short) 1 : (short) 0, false);
        } catch (Throwable t) {
            return fail(t);
        }
    }

    // 0x70 KEYAGREEMENT: P1 = alg, P2 = privSlot; command body = peer public point W.
    // retCode = generateSecret() length; output bytes = secret.
    private short doKeyAgreement(byte alg, byte privSlot, short dataLen) {
        checkSlot(privSlot);
        try {
            PrivateKey key = (PrivateKey) slots[privSlot];
            KeyAgreement ka = KeyAgreement.getInstance(alg, false);
            ka.init(key);
            short n = ka.generateSecret(work, (short) 0, dataLen, out, (short) 3);
            return success(n, true);
        } catch (Throwable t) {
            return fail(t);
        }
    }

    // 0x80 MEMORY: P1=0x00 returns 12 bytes: the 32-bit free counts for persistent,
    // transient-reset, and transient-deselect pools (high word then low word each). P1=0x01
    // requests object deletion and returns 1/0 in retCode for whether the card supports it.
    private short doMemory(byte p1) {
        try {
            if (p1 == P1_MEM_QUERY) {
                writeMemory((short) 3, JCSystem.MEMORY_TYPE_PERSISTENT);
                writeMemory((short) 7, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
                writeMemory((short) 11, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
                return success((short) 12, true);
            }
            if (p1 == P1_MEM_GC) {
                boolean supported = JCSystem.isObjectDeletionSupported();
                if (supported) {
                    JCSystem.requestObjectDeletion();
                }
                return success(supported ? (short) 1 : (short) 0, false);
            }
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            return 0;
        } catch (Throwable t) {
            return fail(t);
        }
    }

    private void writeMemory(short off, byte memoryType) {
        JCSystem.getAvailableMemory(memScratch, (short) 0, memoryType);
        Util.setShort(out, off, memScratch[0]);
        Util.setShort(out, (short) (off + 2), memScratch[1]);
    }

    private void setSymmetricKey(Key key, short dataLen) {
        switch (key.getType()) {
            case KeyBuilder.TYPE_AES:
            case KeyBuilder.TYPE_AES_TRANSIENT_RESET:
            case KeyBuilder.TYPE_AES_TRANSIENT_DESELECT:
                ((AESKey) key).setKey(work, (short) 0);
                break;
            case KeyBuilder.TYPE_DES:
            case KeyBuilder.TYPE_DES_TRANSIENT_RESET:
            case KeyBuilder.TYPE_DES_TRANSIENT_DESELECT:
                ((DESKey) key).setKey(work, (short) 0);
                break;
            case KeyBuilder.TYPE_HMAC:
            case KeyBuilder.TYPE_HMAC_TRANSIENT_RESET:
            case KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT:
                ((HMACKey) key).setKey(work, (short) 0, dataLen);
                break;
            default:
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
    }

    private short getSymmetricKey(Key key) {
        switch (key.getType()) {
            case KeyBuilder.TYPE_AES:
            case KeyBuilder.TYPE_AES_TRANSIENT_RESET:
            case KeyBuilder.TYPE_AES_TRANSIENT_DESELECT:
                return ((AESKey) key).getKey(out, (short) 3);
            case KeyBuilder.TYPE_DES:
            case KeyBuilder.TYPE_DES_TRANSIENT_RESET:
            case KeyBuilder.TYPE_DES_TRANSIENT_DESELECT:
                return ((DESKey) key).getKey(out, (short) 3);
            case KeyBuilder.TYPE_HMAC:
            case KeyBuilder.TYPE_HMAC_TRANSIENT_RESET:
            case KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT:
                return ((HMACKey) key).getKey(out, (short) 3);
            default:
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
                return 0;
        }
    }

    private void setModulus(Key key, short dataLen) {
        if (key.getType() == KeyBuilder.TYPE_RSA_PUBLIC) {
            ((RSAPublicKey) key).setModulus(work, (short) 0, dataLen);
        } else {
            ((RSAPrivateKey) key).setModulus(work, (short) 0, dataLen);
        }
    }

    private short getModulus(Key key) {
        if (key.getType() == KeyBuilder.TYPE_RSA_PUBLIC) {
            return ((RSAPublicKey) key).getModulus(out, (short) 3);
        }
        return ((RSAPrivateKey) key).getModulus(out, (short) 3);
    }

    // Writes SUCCESS at out[0]=0x00, retCode big-endian at out[1..2]. When retData is true,
    // retCode output bytes are already in out[3..] and are included in the returned length.
    private short success(short retCode, boolean retData) {
        out[0] = OUTCOME_SUCCESS;
        Util.setShort(out, (short) 1, retCode);
        return (short) (3 + (retData ? retCode : 0));
    }

    // Writes EXCEPTION at out[0]=0x01, type id at out[1], reason big-endian at out[2..3].
    // Reason is getReason() for CardRuntimeException subclasses (including UserException), else 0.
    private short fail(Throwable t) {
        byte type;
        short reason = 0;
        if (t instanceof CryptoException) {
            type = T_CRYPTO;
            reason = ((CryptoException) t).getReason();
        } else if (t instanceof SystemException) {
            type = T_SYSTEM;
            reason = ((SystemException) t).getReason();
        } else if (t instanceof APDUException) {
            type = T_APDU;
            reason = ((APDUException) t).getReason();
        } else if (t instanceof ISOException) {
            type = T_ISO;
            reason = ((ISOException) t).getReason();
        } else if (t instanceof PINException) {
            type = T_PIN;
            reason = ((PINException) t).getReason();
        } else if (t instanceof TransactionException) {
            type = T_TRANSACTION;
            reason = ((TransactionException) t).getReason();
        } else if (t instanceof UserException) {
            type = T_USER;
            reason = ((UserException) t).getReason();
        } else if (t instanceof CardRuntimeException) {
            type = T_CARD_RUNTIME;
            reason = ((CardRuntimeException) t).getReason();
        } else if (t instanceof ArithmeticException) {
            type = T_ARITHMETIC;
        } else if (t instanceof ArrayIndexOutOfBoundsException) {
            type = T_AIOOBE;
        } else if (t instanceof NullPointerException) {
            type = T_NPE;
        } else if (t instanceof ClassCastException) {
            type = T_CLASS_CAST;
        } else if (t instanceof NegativeArraySizeException) {
            type = T_NEG_ARRAY;
        } else if (t instanceof ArrayStoreException) {
            type = T_ARRAY_STORE;
        } else if (t instanceof IndexOutOfBoundsException) {
            type = T_IOOBE;
        } else {
            type = T_OTHER;
        }
        out[0] = OUTCOME_EXCEPTION;
        out[1] = type;
        Util.setShort(out, (short) 2, reason);
        return 4;
    }

    // Throws SW_INCORRECT_P1P2 when the slot index (treated as unsigned) is out of range.
    private void checkSlot(byte slot) {
        if ((short) (slot & 0xFF) >= slots.length) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }
}
