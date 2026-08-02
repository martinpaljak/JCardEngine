// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.testapplets;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;

import org.globalplatform.GPRegistryEntry;
import org.globalplatform.GPSystem;
import org.globalplatform.GlobalService;
import org.globalplatform.broker.CDCVMBrokerCallbackRequest;

// Drives GPSystem.getRegistryEntry(null).registerService / deregisterService (GPC v2.3.1 8.1.1) on
// its own registry entry, and both ends of Global Service access (8.1.2): it answers as a Global
// Services Application offering the CDCVM broker service, and on request acts as a client looking
// up a service. Reports the outcome SW so tests observe register/deregister behavior.
//
// APDU contract (CLA=0x80, INS=0xEE), CDATA = the 2-byte service name (family, id):
//   P1=0x01 registerService    response = 1 byte 0x01 on success, else 2 bytes = the failure SW
//   P1=0x02 deregisterService  same response convention
//   P1=0x03 getService         CDATA = service name, optionally followed by the provider AID;
//                              response = 2 bytes: service found, service interface is a broker SIO
//   P1=0x04 observed caller    response = the AID seen as previous context in the last requestCallback
public final class GlobalServiceTestApplet extends Applet implements GlobalService, CDCVMBrokerCallbackRequest {

    private static final byte INS = (byte) 0xEE;
    private static final byte P1_REGISTER = (byte) 0x01;
    private static final byte P1_DEREGISTER = (byte) 0x02;
    private static final byte P1_GET_SERVICE = (byte) 0x03;
    private static final byte P1_OBSERVED = (byte) 0x04;

    private AID observed;

    public static void install(byte[] p, short off, byte len) {
        new GlobalServiceTestApplet().register(p, (short) (off + 1), p[off]);
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_INS] != INS) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        short lc = apdu.setIncomingAndReceive();
        if (buf[ISO7816.OFFSET_P1] == P1_GET_SERVICE) {
            getService(apdu, buf, lc);
            return;
        }
        if (buf[ISO7816.OFFSET_P1] == P1_OBSERVED) {
            reportObserved(apdu, buf);
            return;
        }
        if (lc != 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short name = Util.getShort(buf, ISO7816.OFFSET_CDATA);
        try {
            switch (buf[ISO7816.OFFSET_P1]) {
                case P1_REGISTER:
                    GPSystem.getRegistryEntry(null).registerService(name);
                    break;
                case P1_DEREGISTER:
                    GPSystem.getRegistryEntry(null).deregisterService(name);
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            buf[0] = 0x01;
            apdu.setOutgoingAndSend((short) 0, (short) 1);
        } catch (ISOException e) {
            Util.setShort(buf, (short) 0, e.getReason());
            apdu.setOutgoingAndSend((short) 0, (short) 2);
        }
    }

    // Client side of Pull Mode (GPC Amd J v1.1 3.3): looks up the service, then asks it for the SIO.
    private void getService(APDU apdu, byte[] buf, short lc) {
        short name = Util.getShort(buf, ISO7816.OFFSET_CDATA);
        AID server = null;
        if (lc > 2) {
            server = JCSystem.lookupAID(buf, (short) (ISO7816.OFFSET_CDATA + 2), (byte) (lc - 2));
        }
        GlobalService service = GPSystem.getService(server, name);
        buf[0] = 0x00;
        buf[1] = 0x00;
        if (service != null) {
            buf[0] = 0x01;
            Shareable sio = service.getServiceInterface(GPSystem.getRegistryEntry(null), name, null, (short) 0, (short) 0);
            if (sio instanceof CDCVMBrokerCallbackRequest) {
                buf[1] = 0x01;
                ((CDCVMBrokerCallbackRequest) sio).requestCallback((short) 0x0300, (short) 0x0000, REQUEST_CDCVM_LAST_EVENT);
            }
        }
        apdu.setOutgoingAndSend((short) 0, (short) 2);
    }

    private void reportObserved(APDU apdu, byte[] buf) {
        if (observed == null) {
            apdu.setOutgoingAndSend((short) 0, (short) 0);
            return;
        }
        byte length = observed.getBytes(buf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, length);
    }

    @Override
    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
        if (parameter == GPSystem.GLOBAL_SERVICE_IDENTIFIER) {
            return this;
        }
        return null;
    }

    @Override
    public Shareable getServiceInterface(GPRegistryEntry clientRegistryEntry, short sServiceName, byte[] baBuffer, short sOffset, short sLength) {
        if (sServiceName == SERVICE_BROKER_CDCVM) {
            return this;
        }
        return null;
    }

    @Override
    public void requestCallback(short object, short attributes, short request) {
        observed = JCSystem.getPreviousContextAID();
    }
}
