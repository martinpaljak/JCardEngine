/*
 * Copyright 2025 Martin Paljak <martin@martinpaljak.net>
 * Copyright 2015 Licel Corporation.
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

import com.licel.jcardsim.utils.ByteUtil;
import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.ISO7816;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Constructor;
import java.util.Arrays;

// Responsible for all APDU related IO aspects and state holding.
public class CurrentAPDU {
    private static final Logger log = LoggerFactory.getLogger(CurrentAPDU.class);

    // APDU buffer size
    private static final short APDU_BUFFER_SIZE = 261;

    // input block size, for T0 protocol = 1
    public static final short T0_IBS = 1;
    // output block size, for T0 protocol = 258
    public static final short T0_OBS = 258;
    // block size, for T1 protocol
    public static final short T1_BLOCK_SIZE = 254;
    // NAD, for T0 protocol = 9
    private static final byte T0_NAD = 0;

    // transient array to store variables
    private short[] ramVars;
    // LE variable offset in ramVars
    private static final byte LE = 0;
    // LR variable offset in ramVars
    private static final byte LR = 1;
    // LC variable offset in ramVars
    private static final byte LC = 2;
    // total length ramVars
    private static final byte RAM_VARS_LENGTH = 3;

    private int current_pos = 0; // NOTE: must be int or will overflow due to header
    private short remaining_bytes = 0;
    private byte protocol = APDU.PROTOCOL_T0;
    private byte state = APDU.STATE_INITIAL;

    // APDU input buffer
    private final byte[] apdu_buffer;
    // Incoming buffer from where receiveBytes copies from
    private byte[] incoming_buffer;
    // Extended APDU flag
    private boolean extended;
    // If current APDU is available (via process())
    private boolean available = false;
    // APDU class instance (Current APDU for simulator)
    private final APDU apdu;

    CurrentAPDU() {
        apdu_buffer = new byte[APDU_BUFFER_SIZE];
        ramVars = new short[RAM_VARS_LENGTH];

        // Create the APDU instance
        try {
            Constructor<APDU> ctor = APDU.class.getDeclaredConstructor();
            ctor.setAccessible(true);
            this.apdu = ctor.newInstance();
        } catch (Exception e) {
            throw new Error("Could not set up simulator");
        }
    }

    /**
     * Returns the APDU buffer byte array.
     * <p>Note:<ul>
     * <li>References to the APDU buffer byte array
     * cannot be stored in class variables or instance variables or array components.
     * See <em>Runtime
     * Specification for the Java Card Platform</em>, section 6.2.2 for details.
     * </ul>
     *
     * @return byte array containing the APDU buffer
     */
    public byte[] getBuffer() {
        return apdu_buffer;
    }

    /**
     * Returns the configured incoming block size.
     * In T=1 protocol, this corresponds to IFSC (information field size for ICC),
     * the maximum size of incoming data blocks into the card.  In T=0 protocol,
     * this method returns 1.
     * IFSC is defined in ISO 7816-3.<p>
     * This information may be used to ensure that there is enough space remaining in the
     * APDU buffer when <code>receiveBytes()</code> is invoked.
     * <p>Note:
     * <ul>
     * <li><em>On </em><code>receiveBytes()</code><em> the </em><code>bOff</code><em> param
     * should account for this potential blocksize.</em>
     * </ul>
     *
     * @return incoming block size setting
     * @see #receiveBytes(short)
     */
    public short getInBlockSize() {
        return (getProtocol() & APDU.PROTOCOL_T1) == APDU.PROTOCOL_T1 ? T1_BLOCK_SIZE : T0_IBS;
    }

    /**
     * Returns the configured outgoing block size.
     * In T=1 protocol, this corresponds to IFSD (information field size for interface device),
     * the maximum size of outgoing data blocks to the CAD.
     * In T=0 protocol, this method returns 258 (accounts for 2 status bytes).
     * IFSD is defined in ISO 7816-3.
     * <p>This information may be used prior to invoking the <code>setOutgoingLength()</code> method,
     * to limit the length of outgoing messages when BLOCK CHAINING is not allowed.
     * <p>Note:<ul>
     * <li><em>On </em><code>setOutgoingLength()</code><em> the </em><code>len</code><em> param
     * should account for this potential blocksize.</em>
     * </ul>
     *
     * @return outgoing block size setting
     * @see #setOutgoingLength(short)
     */
    public short getOutBlockSize() {
        return (getProtocol() & APDU.PROTOCOL_T1) == APDU.PROTOCOL_T1 ? T1_BLOCK_SIZE : T0_OBS;
    }

    /**
     * Returns the ISO 7816 transport protocol type, T=1 or T=0 in the low nibble
     * and the transport media in the upper nibble in use.
     *
     * @return the protocol media and type in progress
     * Valid nibble codes are listed in PROTOCOL_ .. constants above.
     * @see <CODE>PROTOCOL_T0</CODE>
     */
    public byte getProtocol() {
        return protocol;
    }

    /**
     * Returns the Node Address byte (NAD) in T=1 protocol, and 0
     * in T=0 protocol.
     * This may be used as additional information to maintain multiple contexts.
     *
     * @return NAD transport byte as defined in ISO 7816-3
     */
    public byte getNAD() {
        return T0_NAD;
    }

    /**
     * This method is used to set the data transfer direction to
     * outbound and to obtain the expected length of response (Le). This method
     * should only be called on a case 2 or case 4 command, otherwise erroneous
     * behavior may result.
     * <p>Notes. <ul>
     * <li><em>On a case 4 command, the </em><code>setIncomingAndReceive()</code><em> must
     * be invoked prior to calling this method. Otherwise, erroneous
     * behavior may result in T=0 protocol.</em>
     * <li><em>Any remaining incoming data will be discarded.</em>
     * <li><em>In T=0 (Case 4S) protocol, this method will return 256 with normal
     * semantics.</em>
     * <li><em>In T=0 (Case 2E, 4S) protocol, this method will return 32767 when
     * the currently selected applet implements the
     * </em><code>javacardx.apdu.ExtendedLength</code><em> interface.</em>
     * <li><em>In T=1 (Case 2E, 4E) protocol, this method will return 32767 when the
     * Le field in the APDU command is 0x0000 and the currently selected applet implements the
     * </em><code>javacardx.apdu.ExtendedLength</code><em> interface.</em>
     * <li><em>This method sets the state of the </em><code>APDU</code><em> object to
     * </em><code>STATE_OUTGOING</code><em>.</em>
     * </ul>
     *
     * @return Le, the expected length of response
     * @throws APDUException with the following reason codes:<ul>
     *                       <li><code>APDUException.ILLEGAL_USE</code> if this method, or <code>setOutgoingNoChaining()</code> method already invoked.
     *                       <li><code>APDUException.IO_ERROR</code> on I/O error.
     *                       </ul>
     */
    public short setOutgoing() throws APDUException {
        if (state > APDU.STATE_OUTGOING) {
            APDUException.throwIt(APDUException.ILLEGAL_USE);
        }
        state = APDU.STATE_OUTGOING;
        return ramVars[LE];
    }

    /**
     * This method is used to set the data transfer direction to
     * outbound without using BLOCK CHAINING (See ISO 7816-3/4) and to obtain the expected length of response (Le).
     * This method should be used in place of the
     * <code>setOutgoing()</code> method by applets which need
     * to be compatible with legacy CAD/terminals which do not support ISO 7816-3/4 defined block chaining.
     * See <em>Runtime Environment
     * Specification for the Java Card Platform</em>, section 9.4 for details.
     * <p>Notes. <ul>
     * <li><em>On a case 4 command, the </em><code>setIncomingAndReceive()</code><em> must
     * be invoked prior to calling this method. Otherwise, erroneous
     * behavior may result in T=0 protocol.</em>
     * <li><em>Any remaining incoming data will be discarded.</em>
     * <li><em>In T=0 (Case 4S) protocol, this method will return 256 with normal
     * semantics.</em>
     * <li><em>In T=0 (Case 2E, 4S) protocol, this method will return 256 when
     * the currently selected applet implements the
     * </em><code>javacardx.apdu.ExtendedLength</code><em> interface.</em>
     * <li><em>When this method is used, the </em><code>waitExtension()</code><em> method cannot be used.</em>
     * <li><em>In T=1 protocol, retransmission on error may be restricted.</em>
     * <li><em>In T=0 protocol, the outbound transfer must be performed
     * without using </em><code>(ISO7816.SW_BYTES_REMAINING_00+count)</code><em> response status chaining.</em>
     * <li><em>In T=1 protocol, the outbound transfer must not set the More(M) Bit in the PCB of the I block. See ISO 7816-3.</em>
     * <li><em>This method sets the state of the </em><code>APDU</code><em> object to
     * </em><code>STATE_OUTGOING</code><em>.</em>
     * </ul>
     *
     * @return Le, the expected length of response data
     * @throws APDUException with the following reason codes:<ul>
     *                       <li><code>APDUException.ILLEGAL_USE</code> if this method, or <code>setOutgoingNoChaining()</code> method already invoked.
     *                       <li><code>APDUException.IO_ERROR</code> on I/O error.
     *                       </ul>
     */
    public short setOutgoingNoChaining() throws APDUException {
        if (state >= APDU.STATE_OUTGOING) {
            APDUException.throwIt(APDUException.ILLEGAL_USE);
        }
        state = APDU.STATE_OUTGOING;
        return ramVars[LE];
    }

    /**
     * Sets the actual length of response data. If a length of
     * <code>0</code> is specified, no data will be output.
     * <p>Note:<ul>
     * <li><em>In T=0 (Case 2&amp;4) protocol, the length is used by the Java Card runtime environment to prompt the CAD for GET RESPONSE commands.</em>
     * <li><em>This method sets the state of the
     * <code>APDU</code> object to
     * <code>STATE_OUTGOING_LENGTH_KNOWN</code>.</em>
     * </ul>
     * <p>
     *
     * @param len the length of response data
     * @throws APDUException with the following reason codes:<ul>
     *                       <li><code>APDUException.ILLEGAL_USE</code> if <code>setOutgoing()</code> or <code>setOutgoingNoChaining()</code> not called
     *                       or if <code>setOutgoingAndSend()</code> already invoked, or this method already invoked.
     *                       <li><code>APDUException.BAD_LENGTH</code> if any one of the following is true:<ul>
     *                       <li><code>len</code> is negative.
     *                       <li><code>len</code> is greater than 256 and the currently selected applet does not implement the <code>javacardx.apdu.ExtendedLength</code> interface.
     *                       <li>T=0 protocol is in use, non BLOCK CHAINED data transfer is requested and len is greater than 256.
     *                       <li>T=1 protocol is in use, non BLOCK CHAINED data transfer is requested and len is greater than (IFSD-2), where IFSD is the Outgoing Block Size. The -2 accounts for the status bytes in T=1.
     *                       </ul>
     *                       <li><code>APDUException.NO_T0_GETRESPONSE</code> if T=0 protocol is in use and the CAD does not respond to <code>(ISO7816.SW_BYTES_REMAINING_00+count)</code> response status
     *                       with GET RESPONSE command on the same origin logical channel number as that of the current APDU command.
     *                       <li><code>APDUException.NO_T0_REISSUE</code> if T=0 protocol
     *                       is in use and the CAD does not respond to <code>(ISO7816.SW_CORRECT_LENGTH_00+count)</code> response status by re-issuing same APDU command on the same origin
     *                       logical channel number as that of the current APDU command with the corrected length.
     *                       <li><code>APDUException.IO_ERROR</code> on I/O error.
     *                       </ul>
     * @see #getOutBlockSize()
     */
    public void setOutgoingLength(short len) throws APDUException {
        final short max = extended ? Short.MAX_VALUE : T0_OBS;
        if (state >= APDU.STATE_OUTGOING_LENGTH_KNOWN) {
            APDUException.throwIt(APDUException.ILLEGAL_USE);
        }
        if (len > max || len < 0) {
            APDUException.throwIt(APDUException.BAD_LENGTH);
        }
        state = APDU.STATE_OUTGOING_LENGTH_KNOWN;
        ramVars[LR] = len;
    }

    public short receiveBytes(short bOff) throws APDUException {
        if (state == APDU.STATE_FULL_INCOMING)
            return 0;
        if (state > APDU.STATE_FULL_INCOMING) {
            APDUException.throwIt(APDUException.ILLEGAL_USE);
        }
        if (bOff < 0 || remaining_bytes >= 1 && (bOff + 1) > apdu_buffer.length) {
            APDUException.throwIt(APDUException.BUFFER_BOUNDS);
        }
        if (remaining_bytes != 0) {
            short chunklen = (short) (apdu_buffer.length - bOff);
            if (remaining_bytes < chunklen)
                chunklen = remaining_bytes;
            remaining_bytes -= chunklen;
            System.arraycopy(incoming_buffer, current_pos, apdu_buffer, bOff, chunklen);
            current_pos += chunklen;
            if (remaining_bytes == 0) {
                state = APDU.STATE_FULL_INCOMING;
            } else {
                state = APDU.STATE_PARTIAL_INCOMING;
            }
            return chunklen;
        } else {
            state = APDU.STATE_FULL_INCOMING;
            return 0;
        }
    }

    /**
     * This is the primary receive method.
     * Calling this method indicates that this APDU has incoming data. This method gets as many bytes
     * as will fit without buffer overflow in the APDU buffer following the header.
     * It gets all the incoming bytes if they fit.<p>
     * This method should only be called on a case 3 or case 4 command, otherwise erroneous behavior may result.
     * <p>Notes:
     * <ul>
     * <li><em>In T=0 ( Case 3&amp;4 ) protocol, the P3 param is assumed to be Lc.</em>
     * <li><em>Data is read into the buffer at offset 5 for normal APDU semantics.</em>
     * <li><em>Data is read into the buffer at offset 7 for an extended length APDU (Case 3E/4E).</em>
     * <li><em>In T=1 protocol, if all the incoming bytes do not fit in the buffer, this method may
     * return less bytes than the maximum incoming block size (IFSC).</em>
     * <li><em>In T=0 protocol, if all the incoming bytes do not fit in the buffer, this method may
     * return less than a full buffer of bytes to optimize and reduce protocol overhead.</em>
     * <li><em>This method sets the transfer direction to be inbound
     * and calls <code>receiveBytes(5)</code> for normal semantics or <code>receiveBytes(7)</code> for extended semantics.</em>
     * <li><em>This method may only be called once in a </em><code>Applet.process()</code><em> method.</em>
     * <li><em>This method sets the state of the <code>APDU</code> object to
     * <code>STATE_PARTIAL_INCOMING</code> if all incoming bytes are not received.</em>
     * <li><em>This method sets the state of the <code>APDU</code> object to
     * <code>STATE_FULL_INCOMING</code> if all incoming bytes are received.</em>
     * </ul>
     *
     * @return number of data bytes read. The Le byte, if any, is not included in the count.
     * Returns 0 if no bytes are available.
     * @throws APDUException with the following reason codes:
     *                       <ul>
     *                       <li><code>APDUException.ILLEGAL_USE</code> if <code>setIncomingAndReceive()</code> already invoked or
     *                       if <code>setOutgoing()</code> or <code>setOutgoingNoChaining()</code> previously invoked.
     *                       <li><code>APDUException.IO_ERROR</code> on I/O error.
     *                        <li><code>APDUException.T1_IFD_ABORT</code> if T=1 protocol is in use and the CAD sends
     *                       in an ABORT S-Block command to abort the data transfer.
     *                       </ul>
     */
    public short setIncomingAndReceive() throws APDUException {
        if (state != APDU.STATE_INITIAL) {
            APDUException.throwIt(APDUException.ILLEGAL_USE);
        }
        // NOTE: getOffsetCdata check state.
        return receiveBytes(extended ? ISO7816.OFFSET_EXT_CDATA : ISO7816.OFFSET_CDATA);
    }

    public void sendBytes(short bOff, short len) throws APDUException {
        final short max = extended ? Short.MAX_VALUE : T0_OBS;
        if (bOff < 0 || len < 0 || (short) (bOff + len) > apdu_buffer.length) {
            APDUException.throwIt(APDUException.BUFFER_BOUNDS);
        }
        if (state < APDU.STATE_OUTGOING_LENGTH_KNOWN) {
            APDUException.throwIt(APDUException.ILLEGAL_USE);
        }
        if (len == 0) {
            return;
        }
        short Lr = ramVars[LR];
        if (len > Lr) {
            APDUException.throwIt(APDUException.ILLEGAL_USE);
        }
        Simulator.current().sendAPDU(apdu_buffer, bOff, len);

        Lr -= len;
        if (Lr == 0) {
            state = APDU.STATE_FULL_OUTGOING;
        } else {
            state = APDU.STATE_PARTIAL_OUTGOING;
        }

        ramVars[LR] = Lr;
    }

    /**
     * Sends <code>len</code> more bytes from <code>outData</code> byte array starting at specified offset
     * <code>bOff</code>. <p>If the last of the response is being sent by the invocation
     * of this method, the APDU buffer must not be altered. If the data is altered, incorrect output may be sent to
     * the CAD.
     * Requiring that the buffer not be altered allows the implementation to reduce protocol overhead
     * by transmitting the last part of the response along with the status bytes.
     * <p>The Java Card runtime environment may use the APDU buffer to send data to the CAD.
     * <p>Notes:
     * <ul>
     * <li><em>If </em><code>setOutgoingNoChaining()</code><em> was invoked, output block chaining must not be used.</em>
     * <li><em>In T=0 protocol, if </em><code>setOutgoingNoChaining()</code><em> was invoked, Le bytes must be transmitted
     * before </em><code>(ISO7816.SW_BYTES_REMAINING_00+remaining bytes)</code><em> response status is returned.</em>
     * <li><em>In T=0 protocol, if this method throws an </em><code>APDUException</code><em> with
     * </em><code>NO_T0_GETRESPONSE</code><em> or </em><code>NO_T0_REISSUE</code><em> reason code,
     * the Java Card runtime environment will restart APDU command processing using the newly received command. No more output
     * data can be transmitted. No error status response can be returned.</em>
     * <li><em>In T=1 protocol, if this method throws an </em><code>APDUException</code><em>
     * with </em><code>T1_IFD_ABORT</code><em> reason code, the Java Card runtime environment will restart APDU command processing using the newly
     * received command. No more output data can be transmitted. No error status response can be returned.</em>
     * <li><em>This method sets the state of the <code>APDU</code> object to
     * <code>STATE_PARTIAL_OUTGOING</code> if all outgoing bytes have not been sent.</em>
     * <li><em>This method sets the state of the <code>APDU</code> object to
     * <code>STATE_FULL_OUTGOING</code> if all outgoing bytes have been sent.</em>
     * </ul>
     *
     * @param outData the source data byte array
     * @param bOff    the offset into OutData array
     * @param len     the byte length of the data to send
     * @throws APDUException     with the following reason codes:
     *                           <ul>
     *                           <li><code>APDUException.ILLEGAL_USE</code> if <code>setOutgoingLength()</code> not called
     *                           or <code>setOutgoingAndSend()</code> previously invoked
     *                           or response byte count exceeded or if <code>APDUException.NO_T0_GETRESPONSE</code> or
     *                           <code>APDUException.NO_T0_REISSUE</code> or <code>APDUException.NO_T0_REISSUE</code>
     *                           previously thrown.
     *                           <li><code>APDUException.IO_ERROR</code> on I/O error.
     *                           <li><code>APDUException.NO_T0_GETRESPONSE</code> if T=0 protocol is in use and
     *                           CAD does not respond to <code>(ISO7816.SW_BYTES_REMAINING_00+count)</code> response status
     *                           with GET RESPONSE command on the same origin logical channel number as that of the current
     *                           APDU command.
     *                           <li><code>APDUException.T1_IFD_ABORT</code> if T=1 protocol is in use and the CAD sends
     *                           in an ABORT S-Block command to abort the data transfer.
     *                           </ul>
     * @throws SecurityException if the <code>outData</code> array is not accessible in the caller's context
     * @see #setOutgoing()
     * @see #setOutgoingNoChaining()
     */
    public void sendBytesLong(byte[] outData, short bOff, short len) throws APDUException, SecurityException {
        int sendLength = apdu_buffer.length;
        while (len > 0) {
            if (len < sendLength) {
                sendLength = len;
            }
            System.arraycopy(outData, bOff, apdu_buffer, 0, sendLength);
            sendBytes((short) 0, (short) sendLength);
            len -= sendLength;
            bOff += sendLength;
        }
    }

    /**
     * This is the "convenience" send method. It provides for the most efficient way to send a short
     * response which fits in the buffer and needs the least protocol overhead.
     * This method is a combination of <code>setOutgoing(), setOutgoingLength( len )</code> followed by
     * <code>sendBytes ( bOff, len )</code>. In addition, once this method is invoked, <code>sendBytes()</code> and
     * <code>sendBytesLong()</code> methods cannot be invoked and the APDU buffer must not be altered.<p>
     * Sends <code>len</code> byte response from the APDU buffer starting at the specified offset <code>bOff</code>.
     * <p>Notes:
     * <ul>
     * <li><em>No other </em><code>APDU</code><em> send methods can be invoked.</em>
     * <li><em>The APDU buffer must not be altered. If the data is altered, incorrect output may be sent to
     * the CAD.</em>
     * <li><em>The actual data transmission may only take place on return from </em><code>Applet.process()</code>
     * <li><em>This method sets the state of the <code>APDU</code> object to
     * <code>STATE_FULL_OUTGOING</code>.</em>
     * </ul>
     *
     * @param bOff the offset into APDU buffer
     * @param len  the bytelength of the data to send
     * @throws APDUException ith the following reason codes:
     *                       <ul>
     *                       <li><code>APDUException.ILLEGAL_USE</code> if <code>setOutgoing()</code>
     *                       or <code>setOutgoingAndSend()</code> previously invoked
     *                       or response byte count exceeded.
     *                       <li><code>APDUException.IO_ERROR</code> on I/O error.</ul>
     */
    public void setOutgoingAndSend(short bOff, short len) throws APDUException {
        setOutgoing();
        setOutgoingLength(len);
        sendBytes(bOff, len);
    }

    /**
     * This method returns the current processing state of the
     * <CODE>APDU</CODE> object. It is used by the <CODE>BasicService</CODE> class to help
     * services collaborate in the processing of an incoming APDU command.
     * Valid codes are listed in STATE_ .. constants above.
     *
     * @return the current processing state of the APDU
     * @see APDU#STATE_INITIAL
     */
    public byte getCurrentState() {
        return state;
    }

    /**
     * This method is called during the <code>Applet.process(APDU)</code> method
     * to obtain a reference to the current APDU object.
     * This method can only be called in the context of the currently selected applet.
     * <p>Note:
     * <ul>
     * <li><em>Do not call this method directly or indirectly from within a method
     * invoked remotely via Java Card RMI method invocation from the client. The
     * APDU object and APDU buffer are reserved for use by RMIService. Remote
     * method parameter data may become corrupted.</em>
     * </ul>
     *
     * @return the current <CODE>APDU</CODE> object being processed
     * @throws SecurityException if
     *                           <ul>
     *                           <li>the current context is not the context of the currently selected applet instance or
     *                           <li>this method was not called, directly or indirectly, from the applet's
     *                           process method (called directly by the Java Card runtime environment), or
     *                           <li>the method is called during applet installation or deletion.
     *                           </ul>
     */
    public APDU getCurrentAPDU() throws SecurityException {
        if (!available) {
            throw new SecurityException("getCurrentAPDU must not be called outside of Applet#process()");
        }
        return apdu;
    }


    /**
     * Returns the logical channel number associated with the current <CODE>APDU</CODE> command
     * based on the CLA byte. A number in the range 0-19 based on the CLA byte encoding
     * is returned if the command contains logical channel encoding.
     * If the command does not contain logical channel information, 0 is returned.
     * See <em>Runtime
     * Specification for the Java Card Platform</em>, section
     * 4.3 for encoding details.
     *
     * @return logical channel number, if present, within the CLA byte, 0 otherwise
     */
    public byte getCLAChannel() {
        // FIXME: look at CLA
        return (byte) 0;
    }

    /**
     * Requests additional processing time from CAD. The implementation should ensure that this method
     * needs to be invoked only under unusual conditions requiring excessive processing times.
     * <p>Notes:
     * <ul>
     * <li><em>In T=0 protocol, a NULL procedure byte is sent to reset the work waiting time (see ISO 7816-3).</em>
     * <li><em>In T=1 protocol, the implementation needs to request the same T=0 protocol work waiting time quantum
     * by sending a T=1 protocol request for wait time extension(see ISO 7816-3).</em>
     * <li><em>If the implementation uses an automatic timer mechanism instead, this method may do nothing.</em>
     * </ul>
     *
     * @throws APDUException with the following reason codes:
     *                       <ul>
     *                       <li><code>APDUException.ILLEGAL_USE</code> if <code>setOutgoingNoChaining()</code> previously invoked.
     *                       <li><code>APDUException.IO_ERROR</code> on I/O error.</ul>
     */
    public void waitExtension() throws APDUException {
        // Do nothing.
    }

    /**
     * Returns whether the current
     * <code>APDU</code> command is the first or
     * part of a command chain. Bit b5 of the CLA byte if set, indicates
     * that the
     * <code>APDU</code> is the first or part of a chain of commands.
     * See Runtime Environment Specification for the Java Card Platform, section 4.3 for encoding details.
     *
     * @return <code>true</code> if this APDU is not the last APDU of a command chain, <code>false</code> otherwise.
     * @since 2.2.2
     */
    @SuppressWarnings("unused")
    public boolean isCommandChainingCLA() {
        return (apdu_buffer[ISO7816.OFFSET_CLA] & 0x10) == 0x10;
    }

    /**
     * Returns whether the current APDU command CLA byte is valid. The CLA byte is invalid if the CLA bits (b8,b7,b6) is %b001, which is a CLA encoding reserved for future use(RFU), or if CLA is 0xFF which is an invalid value as defined in the ISO 7816-4:2013 specification.
     * See Runtime Environment Specification, Java Card Platform, Classic Edition, section 4.3 for encoding details.
     *
     * @return true if this APDU CLA byte is valid, false otherwise.
     */
    public boolean isValidCLA() {
        return apdu_buffer[ISO7816.OFFSET_CLA] != (byte) 0xFF && (apdu_buffer[ISO7816.OFFSET_CLA] & 0xE0) != 0x20;
    }

    /**
     * Returns
     * <code>true</code> if the encoding of the current
     * <code>APDU</code>
     * command based on the
     * CLA byte indicates secure messaging. The secure messaging information
     * is in bits (b4,b3) for commands with origin channel numbers 0-3, and in bit
     * b6 for origin channel numbers 4-19.
     * See Runtime Environment Specification for the Java Card Platform, section 4.3 for encoding details.
     *
     * @return <code>true</code> if the secure messaging bit(s) is(are) nonzero, <code>false</code> otherwise
     * @since 2.2.2
     */
    public boolean isSecureMessagingCLA() {
        return (apdu_buffer[ISO7816.OFFSET_CLA] & 0x40) == 0x40 ? (apdu_buffer[ISO7816.OFFSET_CLA] & 0x20) == 0x20 : (apdu_buffer[ISO7816.OFFSET_CLA] & 0x0C) != 0;
    }

    /**
     * Returns whether the current
     * <code>APDU</code> command CLA byte corresponds
     * to an interindustry command as defined in ISO 7816-4:2005 specification.
     * Bit b8 of the CLA byte if
     * <code>0</code>, indicates that the
     * <code>APDU</code>
     * is an interindustry command.
     *
     * @return <code>true</code> if this APDU CLA byte corresponds to an interindustry command, <code>false</code> otherwise.
     * @since 2.2.2
     */
    public boolean isISOInterindustryCLA() {
        return (apdu_buffer[ISO7816.OFFSET_CLA] & 0x80) != 0x80;
    }

    /**
     * Returns the incoming data length(Lc). This method can be invoked
     * whenever inbound data processing methods can be invoked during case 1, 3 or 4
     * processing. It is most useful for an extended length enabled applet to avoid
     * parsing the variable length Lc format in the APDU header.
     *
     * @return the incoming byte length indicated by the Lc field in the APDU header. Return 0 if no incoming data (Case 1)
     * @throws APDUException with the following reason codes:<ul>
     *                       <li><code>APDUException.ILLEGAL_USE</code> if <code>setIncomingAndReceive()</code> not called
     *                       or if <code>setOutgoing()</code> or <code>setOutgoingNoChaining()</code> previously invoked.
     *                       </ul>
     * @see #getOffsetCdata()
     * @since 2.2.2
     */
    public short getIncomingLength() {
        if (state != APDU.STATE_PARTIAL_INCOMING && state != APDU.STATE_FULL_INCOMING) {
            throw new APDUException(APDUException.ILLEGAL_USE);
        }
        return ramVars[LC];
    }

    /**
     * Returns the offset within the APDU buffer for incoming command data.
     * This method can be invoked whenever inbound data processing methods can be
     * invoked during case 1, 3 or 4 processing. It is most useful for an extended
     * length enabled applet to avoid parsing the variable length Lc format in the
     * APDU header.
     *
     * @return the offset within the APDU buffer for incoming command data from the previous call to <code>setIncomingAndReceive()</code> method. The value returned is either 5 (Lc is 1 byte), or 7 (when Lc is 3 bytes)
     * @throws APDUException with the following reason codes:<ul>
     *                       <li><code>APDUException.ILLEGAL_USE</code> if <code>setIncomingAndReceive()</code> not called
     *                       or if <code>setOutgoing()</code> or <code>setOutgoingNoChaining()</code> previously invoked.
     *                       </ul>
     * @see #getIncomingLength()
     * @since 2.2.2
     */
    public short getOffsetCdata() {
        if (state <= APDU.STATE_INITIAL || state > APDU.STATE_FULL_INCOMING) {
            APDUException.throwIt(APDUException.ILLEGAL_USE);
        }
        return extended ? ISO7816.OFFSET_EXT_CDATA : ISO7816.OFFSET_CDATA;
    }

    // Called by Simulator after process() invocation
    void disable() {
        available = false;
    }

    /**
     * clear internal state of the APDU
     */
    void reset(byte protocol, byte[] inputBuffer) {
        Arrays.fill(apdu_buffer, (byte) 0);
        Arrays.fill(ramVars, (short) 0);
        incoming_buffer = inputBuffer.clone();

        // Reset state
        state = APDU.STATE_INITIAL;
        this.protocol = protocol;
        available = true; // make available as current APDU
        int apduCase = APDUHelper.getAPDUCase(inputBuffer);
        extended = APDUHelper.isExtendedAPDU(apduCase);

        // Copy header
        // XXX: it shows how simulator messes with transport layering
        System.arraycopy(incoming_buffer, 0, apdu_buffer, 0, apduCase == APDUHelper.CASE1 ? 4 : (extended ? 7 : 5));
        current_pos = (short) (extended ? 7 : 5);

        final short lc;
        final short le;
        switch (apduCase) {
            case APDUHelper.CASE2: {
                lc = (short) 0;
                final byte leByte = incoming_buffer[ISO7816.OFFSET_LC];
                le = leByte == 0 ? 256 : (short) (0xFF & leByte);
                break;
            }
            case APDUHelper.CASE2_EXTENDED:
                lc = (short) 0;
                le = ByteUtil.getShort(incoming_buffer, ISO7816.OFFSET_LC + 1);
                break;
            case APDUHelper.CASE3:
                lc = (short) (0xFF & incoming_buffer[ISO7816.OFFSET_LC]);
                le = (short) 0;
                break;
            case APDUHelper.CASE3_EXTENDED:
                lc = ByteUtil.getShort(incoming_buffer, ISO7816.OFFSET_LC + 1);
                le = (short) 0;
                break;
            case APDUHelper.CASE4: {
                lc = (short) (0xFF & incoming_buffer[ISO7816.OFFSET_LC]);
                final byte leByte = incoming_buffer[ISO7816.OFFSET_CDATA + lc];
                le = leByte == 0 ? 256 : (short) (0xFF & leByte);
                break;
            }
            case APDUHelper.CASE4_EXTENDED:
                lc = ByteUtil.getShort(incoming_buffer, ISO7816.OFFSET_LC + 1);
                le = ByteUtil.getShort(incoming_buffer, ISO7816.OFFSET_LC + 3 + lc);
                break;
            case APDUHelper.CASE1:
            default:
                lc = (short) 0;
                le = (short) 0;
                break;
        }
        ramVars[LC] = remaining_bytes = lc;
        ramVars[LE] = le;
    }

    public APDU getAPDU() {
        return apdu;
    }
}
