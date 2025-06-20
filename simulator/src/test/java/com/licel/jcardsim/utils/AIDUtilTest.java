package com.licel.jcardsim.utils;

import javacard.framework.AID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AIDUtilTest {

    @Test
    public void testSelectString() {
        assertEquals("00A4040005CAFECAFE0100" ,ByteUtil.hexString(AIDUtil.select("cafecafe01")));
        assertEquals("00A4040001CA00" ,ByteUtil.hexString(AIDUtil.select("ca")));
        assertEquals("00A404000000", ByteUtil.hexString(AIDUtil.select("")));
    }

    @Test
    public void testSelectAID() {
        AID aid = AIDUtil.create("cafecafe01");
        assertEquals("00A4040005CAFECAFE0100" ,ByteUtil.hexString(AIDUtil.select(aid)));
    }
}
