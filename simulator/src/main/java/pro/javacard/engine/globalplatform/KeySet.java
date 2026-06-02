// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import pro.javacard.tlv.TLV;

import java.util.List;
import java.util.SortedMap;
import java.util.TreeMap;

// One KVN's worth of keys held by a security domain. Mirrors GPC v2.3.1 7.5.1: the SD stores
// keys keyed by (KID, KVN); whichever SCP the SD speaks picks up the matching KVN at IU time.
public record KeySet(byte kvn, SortedMap<Byte, KeyEntry> entries) {

    // De facto SCP02/SCP03 KID convention; GPC v2.3.1 7.5.1 says KIDs are arbitrary.
    public static final byte KID_ENC = 0x01;
    public static final byte KID_MAC = 0x02;
    public static final byte KID_DEK = 0x03;

    // GPC v2.3.1 11.1.8 Key Type Coding (Table 11-16).
    public static final byte TYPE_DES3 = (byte) 0x80;
    public static final byte TYPE_AES = (byte) 0x88;

    public record KeyEntry(byte type, byte[] value) {
        public KeyEntry {
            value = value.clone();
        }

        @Override
        public byte[] value() {
            return value.clone();
        }
    }

    // Convenience: one secret used as ENC=MAC=DEK (the bootstrap case).
    public static KeySet ofMaster(byte kvn, byte type, byte[] master) {
        var m = new TreeMap<Byte, KeyEntry>();
        var e = new KeyEntry(type, master);
        m.put(KID_ENC, e);
        m.put(KID_MAC, e);
        m.put(KID_DEK, e);
        return new KeySet(kvn, m);
    }

    public byte[] value(byte kid) {
        return entries.get(kid).value();
    }

    // GPC v2.3.1 11.3.3.1.1 (Table 11-28, Basic) - one C0 per KID. Caller wraps the list in E0.
    public List<TLV> keyInfoEntries() {
        return entries.entrySet().stream()
                .map(e -> TLV.of(0xC0, new byte[]{
                        e.getKey(),
                        kvn,
                        e.getValue().type(),
                        (byte) e.getValue().value().length
                }))
                .toList();
    }
}
