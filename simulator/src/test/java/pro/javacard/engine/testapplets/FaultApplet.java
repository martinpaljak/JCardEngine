package pro.javacard.engine.testapplets;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public class FaultApplet extends Applet {

    byte[] foo;
    boolean blah;

    byte branch = 0;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new FaultApplet().register();
    }

    private FaultApplet() {
        Object tmp = allocator();
        if (!(tmp instanceof byte[])) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        foo = (byte[]) tmp;
        if (foo[0] == 0) {
            blah = true;
        } else if (foo[1] != 0) {
            blah = false;
        }

        if (blah) {
            blah = false;
        }
    }

    private byte[] allocator() {
        return new byte[13];
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        if (buffer[0] == 0 && foo[0] == 0) {
            branch = 1;
            switch (buffer[ISO7816.OFFSET_INS]) {
                case 0x02:
                    branch = 2;
                    break;
                default:
                    branch = 3;
            }
        } else {
            branch = 4;
        }

        //if (1==1)
        //    throw new SecurityException();

        if (branch != 0) {
            throw new SecurityException();
        }
    }
}
