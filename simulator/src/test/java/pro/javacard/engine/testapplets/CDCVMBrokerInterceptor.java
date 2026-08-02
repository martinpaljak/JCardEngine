// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.testapplets;

import javacard.framework.Shareable;
import org.globalplatform.GPRegistryEntry;
import org.globalplatform.GlobalService;
import org.globalplatform.broker.CDCVMBrokerCallbackRequest;

// Pass-through wrapper around a GlobalService obtained from GPSystem.getService(): a CDCVM Pull Mode
// requestCallback() (GPC Amd J v1.1 3.3) is printed to stderr and then forwarded to the real
// broker unchanged, exceptions included. Everything else is handed back untouched.
//
//   GlobalService svc = CDCVMBrokerInterceptor.wrap(GPSystem.getService(null, SERVICE_BROKER_CDCVM));
public final class CDCVMBrokerInterceptor implements GlobalService, CDCVMBrokerCallbackRequest {

    // Allocated once and re-targeted by wrap(), so a call site in a loop allocates nothing.
    private static final CDCVMBrokerInterceptor instance = new CDCVMBrokerInterceptor();

    private GlobalService service;
    private CDCVMBrokerCallbackRequest broker;

    private CDCVMBrokerInterceptor() {
    }

    public static GlobalService wrap(GlobalService service) {
        if (service == null) {
            return null;
        }
        instance.service = service;
        // the SIO of the previously wrapped service does not belong to this one
        instance.broker = null;
        return instance;
    }

    @Override
    public Shareable getServiceInterface(GPRegistryEntry clientRegistryEntry, short sServiceName, byte[] baBuffer, short sOffset, short sLength) {
        Shareable sio = service.getServiceInterface(clientRegistryEntry, sServiceName, baBuffer, sOffset, sLength);
        if (!(sio instanceof CDCVMBrokerCallbackRequest)) {
            return sio;
        }
        broker = (CDCVMBrokerCallbackRequest) sio;
        System.err.println(String.format("CDCVM broker: SIO for service %04X", sServiceName & 0xFFFF));
        return this;
    }

    @Override
    public void requestCallback(short object, short attributes, short request) {
        System.err.println(String.format("CDCVM broker: requestCallback object %04X attributes %04X request %04X",
                object & 0xFFFF, attributes & 0xFFFF, request & 0xFFFF));
        broker.requestCallback(object, attributes, request);
    }
}
