/*
 * Copyright 2025 Martin Paljak <martin@martinpaljak.net>
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
package pro.javacard.engine.proxy.javacard.framework;

import com.licel.jcardsim.base.Simulator;
import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.ISOException;

public final class APDUProxy {

    public static short getInBlockSize() {
        return Simulator.current().getCurrentAPDU().getInBlockSize();
    }

    public static short getOutBlockSize() {
        return Simulator.current().getCurrentAPDU().getOutBlockSize();
    }

    public static APDU getCurrentAPDU() {
        return Simulator.current().getCurrentAPDU().getCurrentAPDU();
    }

    public static byte[] getCurrentAPDUBuffer() {
        return getCurrentAPDU().getBuffer();
    }

    public static byte getCLAChannel() {
        return Simulator.current().getCurrentAPDU().getCLAChannel();
    }

    public static void waitExtension() {
        Simulator.current().getCurrentAPDU().waitExtension();
    }

    public static byte getProtocol() {
        return Simulator.current().getCurrentAPDU().getProtocol();
    }

    public byte[] getBuffer() {
        return Simulator.current().getCurrentAPDU().getBuffer();
    }

    public byte getNAD() {
        return Simulator.current().getCurrentAPDU().getNAD();
    }

    public short setOutgoing() throws APDUException, ISOException {
        return Simulator.current().getCurrentAPDU().setOutgoing();
    }

    public short setOutgoingNoChaining() throws APDUException, ISOException {
        return Simulator.current().getCurrentAPDU().setOutgoingNoChaining();
    }

    public void setOutgoingLength(short length) throws APDUException {
        Simulator.current().getCurrentAPDU().setOutgoingLength(length);
    }

    public short receiveBytes(short length) throws APDUException {
        return Simulator.current().getCurrentAPDU().receiveBytes(length);
    }

    public short setIncomingAndReceive() throws APDUException {
        return Simulator.current().getCurrentAPDU().setIncomingAndReceive();
    }

    public void sendBytes(short offset, short length) throws APDUException {
        Simulator.current().getCurrentAPDU().sendBytes(offset, length);
    }

    public void sendBytesLong(byte[] buffer, short offset, short length) throws APDUException, SecurityException {
        Simulator.current().getCurrentAPDU().sendBytesLong(buffer, offset, length);
    }

    public void setOutgoingAndSend(short offset, short length) throws APDUException {
        Simulator.current().getCurrentAPDU().setOutgoingAndSend(offset, length);
    }

    public byte getCurrentState() {
        return Simulator.current().getCurrentAPDU().getCurrentState();
    }

    public boolean isCommandChainingCLA() {
        return Simulator.current().getCurrentAPDU().isCommandChainingCLA();
    }

    public boolean isSecureMessagingCLA() {
        return Simulator.current().getCurrentAPDU().isSecureMessagingCLA();
    }

    public boolean isISOInterindustryCLA() {
        return Simulator.current().getCurrentAPDU().isISOInterindustryCLA();
    }

    public boolean isValidCLA() {
        return Simulator.current().getCurrentAPDU().isValidCLA();
    }

    public short getIncomingLength() {
        return Simulator.current().getCurrentAPDU().getIncomingLength();
    }

    public short getOffsetCdata() {
        return Simulator.current().getCurrentAPDU().getOffsetCdata();
    }

}
