/*
 * Copyright 2011 Licel LLC.
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
package com.licel.jcardsim.base;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Locale;
import java.util.Objects;

import com.licel.jcardsim.utils.AIDUtil;
import com.licel.jcardsim.utils.ByteUtil;
import javacard.framework.*;
import org.bouncycastle.util.encoders.Hex;

/**
 * Simulates a JavaCard.
 */
public class Simulator implements CardInterface {
    // default ATR - NXP JCOP 31/36K
    public static final String DEFAULT_ATR = "3BFA1800008131FE454A434F5033315632333298";
    // ATR system property name
    public static final String ATR_SYSTEM_PROPERTY = "com.licel.jcardsim.card.ATR";

    // Runtime
    protected final SimulatorRuntime runtime;
    // current protocol
    private String protocol = "T=0";

    /**
     * Create a Simulator object using the default SimulatorRuntime.
     *
     * <ul>
     *     <li>All <code>Simulator</code> instances share one <code>SimulatorRuntime</code>.</li>
     *     <li>SimulatorRuntime#resetRuntime is called</li>
     *     <li>If you want multiple independent simulators use <code>Simulator(SimulatorRuntime)</code></li>
     * </ul>
     */
    public Simulator() {
        this(SimulatorSystem.DEFAULT_RUNTIME);
    }

    public Simulator(SimulatorRuntime runtime) {
        if (runtime == null) {
            throw new NullPointerException("runtime");
        }

        this.runtime = runtime;
        synchronized (this.runtime) {
            this.runtime.resetRuntime();
        }

        changeProtocol(protocol);
    }

    /**
     * Load
     * <code>Applet</code> into Simulator
     *
     * @param aid         applet aid
     * @param appletClass applet class
     * @return applet <code>AID</code>
     * @throws SystemException if <code>appletClass</code> not instanceof
     *                         <code>javacard.framework.Applet</code>
     */
    public AID loadApplet(AID aid, Class<? extends Applet> appletClass) throws SystemException {
        synchronized (runtime) {
            runtime.loadApplet(aid, appletClass);
        }
        return aid;
    }

    public AID createApplet(AID aid, byte bArray[], short bOffset, byte bLength) throws SystemException {

        try {
            synchronized (runtime) {
                runtime.installApplet(aid, bArray, bOffset, bLength);
            }
        } catch (Exception e) {
            e.printStackTrace();
            SystemException.throwIt(SimulatorSystem.SW_APPLET_CREATION_FAILED);
        }
        return aid;
    }

    /**
     * Install
     * <code>Applet</code> into Simulator without installing data
     *
     * @param aid         applet aid or null
     * @param appletClass applet class
     * @return applet <code>AID</code>
     * @throws SystemException if <code>appletClass</code> not instanceof
     *                         <code>javacard.framework.Applet</code>
     */
    public AID installApplet(AID aid, Class<? extends Applet> appletClass) throws SystemException {
        return installApplet(aid, appletClass, new byte[]{}, (short) 0, (byte) 0);
    }

    /**
     * Install
     * <code>Applet</code> into Simulator. This method is equal to:
     * <code>
     * loadApplet(...);
     * createApplet(...);
     * </code>
     *
     * @param aid         applet aid or null
     * @param appletClass applet class
     * @param bArray      the array containing installation parameters
     * @param bOffset     the starting offset in bArray
     * @param bLength     the length in bytes of the parameter data in bArray
     * @return applet <code>AID</code>
     * @throws SystemException if <code>appletClass</code> not instanceof
     *                         <code>javacard.framework.Applet</code>
     */
    public AID installApplet(AID aid, Class<? extends Applet> appletClass, byte bArray[], short bOffset,
                             byte bLength) throws SystemException {
        synchronized (runtime) {
            loadApplet(aid, appletClass);
            return createApplet(aid, bArray, bOffset, bLength);
        }
    }

    /**
     * Delete an applet
     *
     * @param aid applet aid
     */
    public void deleteApplet(AID aid) {
        synchronized (runtime) {
            runtime.deleteApplet(aid);
        }
    }

    public boolean selectApplet(AID aid) throws SystemException {
        byte[] resp = selectAppletWithResult(aid);
        return ByteUtil.getSW(resp) == ISO7816.SW_NO_ERROR;
    }

    public byte[] selectAppletWithResult(AID aid) throws SystemException {
        synchronized (runtime) {
            return runtime.transmitCommand(AIDUtil.select(aid));
        }
    }

    public byte[] transmitCommand(byte[] command) {
        synchronized (runtime) {
            return runtime.transmitCommand(command);
        }
    }

    public void reset() {
        synchronized (runtime) {
            runtime.reset();
        }
    }

    public final void resetRuntime() {
        synchronized (runtime) {
            runtime.resetRuntime();
        }
    }

    public byte[] getATR() {
        return Hex.decode(System.getProperty(ATR_SYSTEM_PROPERTY, DEFAULT_ATR));
    }

    protected byte getProtocolByte(String protocol) {
        Objects.requireNonNull(protocol, "protocol");
        String p = protocol.toUpperCase(Locale.ENGLISH).replace(" ", "");
        byte protocolByte;

        if (p.equals("T=0") || p.equals("*")) {
            protocolByte = APDU.PROTOCOL_T0;
        } else if (p.equals("T=1")) {
            protocolByte = APDU.PROTOCOL_T1;
        } else if (p.equals("T=CL,TYPE_A,T1") || p.equals("T=CL")) {
            protocolByte = APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A;
            protocolByte |= APDU.PROTOCOL_T1;
        } else if (p.equals("T=CL,TYPE_B,T1")) {
            protocolByte = APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B;
            protocolByte |= APDU.PROTOCOL_T1;
        } else {
            throw new IllegalArgumentException("Unknown protocol: " + protocol);
        }
        return protocolByte;
    }

    /**
     * Switch protocol
     * <p>
     * Supported protocols are:
     * <ul>
     *     <li><code>T=0</code> (alias: <code>*</code>)</li>
     *     <li><code>T=1</code></li>
     *     <li><code>T=CL, TYPE_A, T1</code></li>
     *     <li><code>T=CL, TYPE_B, T1</code></li>
     * </ul>
     *
     * @param protocol protocol to use
     * @throws java.lang.IllegalArgumentException for unknown protocols
     */
    // XXX: changing protocol during session is not really a thing.
    public void changeProtocol(String protocol) {
        synchronized (runtime) {
            runtime.changeProtocol(getProtocolByte(protocol));
            this.protocol = protocol;
        }
    }

    /**
     * @return the current protocol string
     * @see #changeProtocol(String)
     */
    public String getProtocol() {
        return protocol;
    }

    public static byte[] install_parameters(byte[] aid, byte[] data) {
        if (data == null)
            data = new byte[0];
        byte[] fullData = new byte[1 + aid.length + 1 + 1 + 1 + data.length];
        int offset = 0;
        fullData[offset++] = (byte) aid.length;
        System.arraycopy(aid, 0, fullData, offset, aid.length);
        offset += aid.length;
        // NOTE: dummy privileges
        fullData[offset++] = 0x01;
        fullData[offset++] = 0x00;
        fullData[offset++] = (byte) data.length;
        System.arraycopy(data, 0, fullData, offset, data.length);
        return fullData;
    }
}
