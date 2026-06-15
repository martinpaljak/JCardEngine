// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import pro.javacard.tlv.TLV;

import java.io.ByteArrayOutputStream;
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
    public static final byte TYPE_RSA_PUB_EXP = (byte) 0xA0; // exponent e, transmitted in clear
    public static final byte TYPE_RSA_PUB_MOD = (byte) 0xA1; // modulus N, transmitted in clear

    // GPC v2.3.1 11.8.2.3.1: symmetric keys have one component; RSA public keys have two (N and e).
    public record KeyComponent(byte type, byte[] value) {
        public KeyComponent {
            value = value.clone();
        }

        @Override
        public byte[] value() {
            return value.clone();
        }
    }

    public record KeyEntry(List<KeyComponent> components) {
        public KeyEntry {
            components = List.copyOf(components);
        }

        // Convenience for single-component keys (SCP keys, KCV handling).
        public KeyEntry(byte type, byte[] value) {
            this(List.of(new KeyComponent(type, value)));
        }

        private KeyComponent single() {
            if (components.size() != 1) {
                throw new IllegalStateException("not a single-component key: " + components.size());
            }
            return components.get(0);
        }

        public byte type() {
            return single().type();
        }

        public byte[] value() {
            return single().value();
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

    // Asymmetric keys (e.g. an RSA token-verification key) live in the SD but are not SCP keysets,
    // so they must stay invisible to SCP keyset selection and factory eviction.
    public boolean isSCP() {
        return entries.values().stream().allMatch(e -> e.components().size() == 1
                && (e.components().get(0).type() == TYPE_DES3 || e.components().get(0).type() == TYPE_AES));
    }

    // GPC v2.3.1 11.3.3.1.1 (Table 11-28, Basic) - one C0 per (KID, KVN). Component length >= 256
    // (e.g. an RSA modulus) is coded '00'. Caller wraps in E0.
    public List<TLV> keyInfoEntries() {
        return entries.entrySet().stream()
                .map(e -> {
                    var bo = new ByteArrayOutputStream();
                    bo.write(e.getKey());
                    bo.write(kvn);
                    for (var c : e.getValue().components()) {
                        bo.write(c.type());
                        bo.write(c.value().length >= 256 ? 0x00 : c.value().length);
                    }
                    return TLV.of(0xC0, bo.toByteArray());
                })
                .toList();
    }
}
