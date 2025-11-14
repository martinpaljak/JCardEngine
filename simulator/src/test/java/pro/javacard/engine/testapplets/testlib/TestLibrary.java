package pro.javacard.engine.testapplets.testlib;

import javacard.framework.ISO7816;

public class TestLibrary {

    public static short valueHelper() {
        return ISO7816.SW_CLA_NOT_SUPPORTED;
    }
}
