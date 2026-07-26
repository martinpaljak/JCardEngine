// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.crypto;

import apdu4j.core.BIBO;
import apdu4j.core.GetResponseWrapper;
import apdu4j.core.HexUtils;
import apdu4j.pcsc.CardBIBO;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DefaultBufferedBlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;

import org.testng.SkipException;
import org.testng.annotations.Test;
import static org.testng.Assert.*;

import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import pro.javacard.engine.crypto.CryptoProber.Result;
import pro.javacard.engine.testapplets.CryptoProbeApplet;

// Drives CryptoProbeApplet over a BIBO and cross-checks every result against a BouncyCastle oracle.
public class CryptoParityTest {

    private static final String AID = "D23300000077" + "4352592D3031" + "01";

    private static final byte[] INPUT = makeInput();

    // Key slot indices in CryptoProbeApplet's slot array.
    private static final int SLOT_PUB_A = 0;
    private static final int SLOT_PRIV_A = 1;
    private static final int SLOT_PUB_B = 2;
    private static final int SLOT_PRIV_B = 3;
    private static final int SLOT_RSA_PUB = 4;
    private static final int SLOT_RSA_PRIV = 5;
    private static final int SLOT_SYM = 6;

    // GEN: card generates the keypair. INJECT: host generates and loads it into the slots.
    private enum KeyMode {GEN, INJECT}

    @Test
    public void jcardengine() {
        var sim = new Simulator();
        sim.installApplet(AIDUtil.create(AID), CryptoProbeApplet.class);
        try (BIBO bibo = sim.connect()) {
            run(bibo);
        }
    }

    @Test
    public void pcsc() throws Exception {
        String name = System.getenv("PROBE_READER");
        if (name == null || name.isEmpty()) {
            throw new SkipException("PROBE_READER not set");
        }
        CardTerminal terminal = TerminalFactory.getDefault().terminals().list().stream()
                .filter(t -> t.getName().equals(name)).findFirst()
                .orElseThrow(() -> new IllegalStateException("reader not found: " + name));
        var card = terminal.connect("*");
        try (BIBO bibo = CardBIBO.wrap(card).then(GetResponseWrapper::wrap)) {
            run(bibo);
        }
    }

    private void run(BIBO bibo) {
        var prober = new CryptoProber(bibo);
        prober.select(AIDUtil.bytes(AIDUtil.create(AID)));
        long[] memStart = reportMemory(prober, "start");
        runDigests(prober);
        runCiphers(prober);
        runComponentReadback(prober);
        runEcdsa(prober);
        runEcdh(prober);
        runRsa(prober);
        prober.gc();
        long[] memEnd = reportMemory(prober, "end");
        if (memStart != null && memEnd != null) {
            // positive delta = bytes consumed across the run (pool shrank)
            System.out.println("MEMORY delta persistent=%d transient_reset=%d transient_deselect=%d"
                    .formatted(memStart[0] - memEnd[0], memStart[1] - memEnd[1], memStart[2] - memEnd[2]));
        }
    }

    // Returns free memory across the three pools, or null if the card does not support the query.
    private static long[] reportMemory(CryptoProber prober, String when) {
        var m = prober.memory();
        if (!m.ok() || m.output().length < 12) {
            System.out.println("MEMORY " + when + " : unavailable");
            return null;
        }
        byte[] o = m.output();
        long[] v = {u32(o, 0), u32(o, 4), u32(o, 8)};
        System.out.println("MEMORY %s persistent=%d transient_reset=%d transient_deselect=%d".formatted(when, v[0], v[1], v[2]));
        return v;
    }

    private static long u32(byte[] b, int off) {
        return ((long) (b[off] & 0xFF) << 24) | ((b[off + 1] & 0xFF) << 16) | ((b[off + 2] & 0xFF) << 8) | (b[off + 3] & 0xFF);
    }

    // Digests

    private record Alg(int id, String name, Digest bc) {
    }

    private static List<Alg> digestAlgs() {
        return List.of(
                new Alg(MessageDigest.ALG_SHA, "SHA-1", new SHA1Digest()),
                new Alg(MessageDigest.ALG_MD5, "MD5", new MD5Digest()),
                new Alg(MessageDigest.ALG_RIPEMD160, "RIPEMD160", new RIPEMD160Digest()),
                new Alg(MessageDigest.ALG_SHA_224, "SHA-224", new SHA224Digest()),
                new Alg(MessageDigest.ALG_SHA_256, "SHA-256", new SHA256Digest()),
                new Alg(MessageDigest.ALG_SHA_384, "SHA-384", new SHA384Digest()),
                new Alg(MessageDigest.ALG_SHA_512, "SHA-512", new SHA512Digest()),
                new Alg(MessageDigest.ALG_SHA3_224, "SHA3-224", new SHA3Digest(224)),
                new Alg(MessageDigest.ALG_SHA3_256, "SHA3-256", new SHA3Digest(256)),
                new Alg(MessageDigest.ALG_SHA3_384, "SHA3-384", new SHA3Digest(384)),
                new Alg(MessageDigest.ALG_SHA3_512, "SHA3-512", new SHA3Digest(512)));
    }

    private void runDigests(CryptoProber prober) {
        runGroup("DIGESTS", digestAlgs(), a -> {
            var r = prober.digest(a.id(), INPUT);
            if (r.noSuchAlgorithm()) {
                return new Skip("DIGEST skip " + a.name() + " : NO_SUCH_ALGORITHM");
            }
            if (!r.ok()) {
                return new Fail("DIGEST %s %s".formatted(a.name(), exc(r)));
            }
            byte[] bcOut = digest(a.bc(), INPUT);
            if (Arrays.equals(r.output(), bcOut)) {
                return new Pass(null);
            }
            return new Fail("DIGEST %s engine=%s bc=%s".formatted(a.name(), HexUtils.bin2hex(r.output()), HexUtils.bin2hex(bcOut)));
        });
    }

    // Ciphers

    private enum Pad {NOPAD, M1, M2, PKCS5}

    private enum Sym {AES, DES}

    private record CipherCase(String name, int alg, Sym sym, boolean cbc, boolean ctr, Pad pad) {
    }

    private static List<CipherCase> cipherCases() {
        return List.of(
                new CipherCase("DES_CBC_NOPAD", Cipher.ALG_DES_CBC_NOPAD, Sym.DES, true, false, Pad.NOPAD),
                new CipherCase("DES_CBC_ISO9797_M1", Cipher.ALG_DES_CBC_ISO9797_M1, Sym.DES, true, false, Pad.M1),
                new CipherCase("DES_CBC_ISO9797_M2", Cipher.ALG_DES_CBC_ISO9797_M2, Sym.DES, true, false, Pad.M2),
                new CipherCase("DES_CBC_PKCS5", Cipher.ALG_DES_CBC_PKCS5, Sym.DES, true, false, Pad.PKCS5),
                new CipherCase("DES_ECB_NOPAD", Cipher.ALG_DES_ECB_NOPAD, Sym.DES, false, false, Pad.NOPAD),
                new CipherCase("DES_ECB_ISO9797_M1", Cipher.ALG_DES_ECB_ISO9797_M1, Sym.DES, false, false, Pad.M1),
                new CipherCase("DES_ECB_ISO9797_M2", Cipher.ALG_DES_ECB_ISO9797_M2, Sym.DES, false, false, Pad.M2),
                new CipherCase("DES_ECB_PKCS5", Cipher.ALG_DES_ECB_PKCS5, Sym.DES, false, false, Pad.PKCS5),
                new CipherCase("AES_BLOCK_128_CBC_NOPAD", Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, Sym.AES, true, false, Pad.NOPAD),
                new CipherCase("AES_BLOCK_128_ECB_NOPAD", Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, Sym.AES, false, false, Pad.NOPAD),
                new CipherCase("AES_CBC_ISO9797_M1", Cipher.ALG_AES_CBC_ISO9797_M1, Sym.AES, true, false, Pad.M1),
                new CipherCase("AES_CBC_ISO9797_M2", Cipher.ALG_AES_CBC_ISO9797_M2, Sym.AES, true, false, Pad.M2),
                new CipherCase("AES_CBC_PKCS5", Cipher.ALG_AES_CBC_PKCS5, Sym.AES, true, false, Pad.PKCS5),
                new CipherCase("AES_ECB_ISO9797_M1", Cipher.ALG_AES_ECB_ISO9797_M1, Sym.AES, false, false, Pad.M1),
                new CipherCase("AES_ECB_ISO9797_M2", Cipher.ALG_AES_ECB_ISO9797_M2, Sym.AES, false, false, Pad.M2),
                new CipherCase("AES_ECB_PKCS5", Cipher.ALG_AES_ECB_PKCS5, Sym.AES, false, false, Pad.PKCS5),
                new CipherCase("AES_CTR", Cipher.ALG_AES_CTR, Sym.AES, false, true, Pad.NOPAD));
    }

    private static List<Integer> keyBits(Sym sym) {
        return sym == Sym.AES ? List.of(128, 192, 256) : List.of(64, 128, 192);
    }

    private void runCiphers(CryptoProber prober) {
        var rnd = seeded();
        runGroupMulti("CIPHERS", cipherCases(), cc -> keyBits(cc.sym()).stream()
                .map(bits -> runCipher(prober, cc, bits, rnd))
                .toList());
    }

    // Checks card/BC interop in both directions (card-enc/BC-dec and BC-enc/card-dec). Does not
    // check ciphertext byte identity, only that each side recovers plaintext.
    private Outcome runCipher(CryptoProber prober, CipherCase cc, int keyBits, SecureRandom rnd) {
        int blockSize = cc.sym() == Sym.AES ? 16 : 8;
        byte[] keyBytes = new byte[keyBits / 8];
        rnd.nextBytes(keyBytes);
        byte[] iv = new byte[blockSize];
        rnd.nextBytes(iv);
        int ptLen = cc.pad() == Pad.NOPAD && !cc.ctr() ? blockSize * 2 : blockSize * 2 + 3;
        byte[] pt = new byte[ptLen];
        rnd.nextBytes(pt);

        String tag = cc.name() + "/" + keyBits;
        var built = buildSymKey(prober, cc.sym(), keyBits);
        if (!built.ok()) {
            return new Skip("CIPHER skip %s : buildKey %s".formatted(tag, exc(built)));
        }
        var set = prober.setComponent(SLOT_SYM, CryptoProber.COMP_SYMMETRIC, keyBytes);
        if (!set.ok()) {
            return new Skip("CIPHER skip %s : setKey %s".formatted(tag, exc(set)));
        }

        byte[] cipherIv = cc.cbc() || cc.ctr() ? iv : null;

        // card encrypts, BC decrypts
        var enc = prober.cipher(cc.alg(), CryptoProber.MODE_ENCRYPT, SLOT_SYM, cipherIv, pt);
        if (enc.noSuchAlgorithm()) {
            return new Skip("CIPHER skip %s : NO_SUCH_ALGORITHM".formatted(tag));
        }
        if (!enc.ok()) {
            return new Fail("CIPHER %s enc %s".formatted(tag, exc(enc)));
        }
        byte[] bcRecovered = bcCrypt(cc, keyBytes, iv, enc.output(), false);
        if (!recovers(cc, pt, bcRecovered)) {
            return new Fail("CIPHER %s card-enc/BC-dec did not recover pt=%s got=%s".formatted(tag, HexUtils.bin2hex(pt), HexUtils.bin2hex(bcRecovered)));
        }

        // BC encrypts, card decrypts
        byte[] bcCt = bcCrypt(cc, keyBytes, iv, pt, true);
        var dec = prober.cipher(cc.alg(), CryptoProber.MODE_DECRYPT, SLOT_SYM, cipherIv, bcCt);
        if (!dec.ok()) {
            return new Fail("CIPHER %s dec %s".formatted(tag, exc(dec)));
        }
        if (!recovers(cc, pt, dec.output())) {
            return new Fail("CIPHER %s BC-enc/card-dec did not recover pt=%s got=%s".formatted(tag, HexUtils.bin2hex(pt), HexUtils.bin2hex(dec.output())));
        }
        return new Pass("CIPHER %s ok card-ct-len=%d recovered both directions".formatted(tag, enc.output().length));
    }

    // ISO 9797-1 M1 (zero padding) may leave trailing zero bytes; compare after trimming.
    // All other padding schemes recover plaintext exactly.
    private static boolean recovers(CipherCase cc, byte[] pt, byte[] recovered) {
        if (cc.pad() == Pad.M1) {
            return Arrays.equals(trimZeros(pt), trimZeros(recovered));
        }
        return Arrays.equals(pt, recovered);
    }

    private static byte[] trimZeros(byte[] a) {
        int n = a.length;
        while (n > 0 && a[n - 1] == 0) {
            n--;
        }
        return Arrays.copyOf(a, n);
    }

    private static Result buildSymKey(CryptoProber prober, Sym sym, int keyBits) {
        if (sym == Sym.AES) {
            int len = switch (keyBits) {
                case 128 -> KeyBuilder.LENGTH_AES_128;
                case 192 -> KeyBuilder.LENGTH_AES_192;
                case 256 -> KeyBuilder.LENGTH_AES_256;
                default -> throw new IllegalArgumentException();
            };
            return prober.newKeyWithFallback(SLOT_SYM, KeyBuilder.ALG_TYPE_AES, KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.TYPE_AES, len);
        }
        int len = switch (keyBits) {
            case 64 -> KeyBuilder.LENGTH_DES;
            case 128 -> KeyBuilder.LENGTH_DES3_2KEY;
            case 192 -> KeyBuilder.LENGTH_DES3_3KEY;
            default -> throw new IllegalArgumentException();
        };
        return prober.newKeyWithFallback(SLOT_SYM, KeyBuilder.ALG_TYPE_DES, KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, KeyBuilder.TYPE_DES, len);
    }

    // BC reference run for a symmetric case, in either direction; encrypt selects init's processing mode.
    private static byte[] bcCrypt(CipherCase cc, byte[] keyBytes, byte[] iv, byte[] in, boolean encrypt) {
        BlockCipher base = switch (cc.sym()) {
            case AES -> AESEngine.newInstance();
            case DES -> keyBytes.length == 8 ? new DESEngine() : new DESedeEngine();
        };
        if (cc.ctr()) {
            var buf = new DefaultBufferedBlockCipher(SICBlockCipher.newInstance(base));
            buf.init(encrypt, new ParametersWithIV(new KeyParameter(keyBytes), iv));
            return finish(buf, in);
        }
        BlockCipher modeCipher = cc.cbc() ? CBCBlockCipher.newInstance(base) : base;
        BlockCipherPadding padding = switch (cc.pad()) {
            case NOPAD -> null;
            case M1 -> new ZeroBytePadding();
            case M2 -> new ISO7816d4Padding();
            case PKCS5 -> new PKCS7Padding();
        };
        BufferedBlockCipher buf = padding == null
                ? new DefaultBufferedBlockCipher(modeCipher)
                : new PaddedBufferedBlockCipher(modeCipher, padding);
        if (cc.cbc()) {
            buf.init(encrypt, new ParametersWithIV(new KeyParameter(keyBytes), iv));
        } else {
            buf.init(encrypt, new KeyParameter(keyBytes));
        }
        return finish(buf, in);
    }

    // Pushes the whole input through an initialised cipher and returns exactly the produced bytes.
    private static byte[] finish(BufferedBlockCipher buf, byte[] in) {
        byte[] out = new byte[buf.getOutputSize(in.length)];
        int len = buf.processBytes(in, 0, in.length, out, 0);
        try {
            len += buf.doFinal(out, len);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
        return Arrays.copyOf(out, len);
    }

    // EC curves

    private static final String[] PRIME_CURVES = {
            "secp192r1", "secp224r1", "secp256r1", "secp384r1", "secp521r1",
            "secp192k1", "secp224k1", "secp256k1",
            "brainpoolP160r1", "brainpoolP160t1", "brainpoolP192r1", "brainpoolP192t1",
            "brainpoolP224r1", "brainpoolP224t1", "brainpoolP256r1", "brainpoolP256t1",
            "brainpoolP320r1", "brainpoolP320t1", "brainpoolP384r1", "brainpoolP384t1",
            "brainpoolP512r1", "brainpoolP512t1"};

    private record Curve(String name, X9ECParameters x9, ECDomainParameters dom, int fieldBytes, int fieldBits) {
    }

    private static final Map<String, Curve> CURVE_CACHE = new ConcurrentHashMap<>();

    private static Curve curve(String name) {
        return CURVE_CACHE.computeIfAbsent(name, CryptoParityTest::parseCurve);
    }

    private static Curve parseCurve(String name) {
        var x9 = CustomNamedCurves.getByName(name);
        if (x9 == null) {
            x9 = ECNamedCurveTable.getByName(name);
        }
        var dom = new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH());
        var fieldBits = x9.getCurve().getFieldSize();
        var fieldBytes = (fieldBits + 7) / 8;
        return new Curve(name, x9, dom, fieldBytes, fieldBits);
    }

    private static byte[] fixed(BigInteger v, int len) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[len];
        if (raw.length == len) {
            return raw;
        }
        if (raw.length == len + 1 && raw[0] == 0) {
            System.arraycopy(raw, 1, out, 0, len);
            return out;
        }
        if (raw.length < len) {
            System.arraycopy(raw, 0, out, len - raw.length, raw.length);
            return out;
        }
        System.arraycopy(raw, raw.length - len, out, 0, len);
        return out;
    }

    // Builds both key objects, injects the curve parameters verbatim, and either generates the
    // keypair on-card (GEN) or loads a host-generated (S, W) pair (INJECT). Returns a Step carrying
    // the card's CryptoException whenever the card refuses a step, or null when the pair is ready.
    private Step buildEcKeyPair(CryptoProber prober, Curve c, int pubSlot, int privSlot, KeyMode mode) {
        var pub = prober.newKey(pubSlot, 0, KeyBuilder.TYPE_EC_FP_PUBLIC, c.fieldBits());
        if (!pub.ok()) {
            return Step.skip("buildKey pub field %d %s".formatted(c.fieldBits(), exc(pub)));
        }
        var priv = prober.newKey(privSlot, 0, KeyBuilder.TYPE_EC_FP_PRIVATE, c.fieldBits());
        if (!priv.ok()) {
            return Step.skip("buildKey priv field %d %s".formatted(c.fieldBits(), exc(priv)));
        }
        var inj = injectCurve(prober, pubSlot, c);
        if (inj != null) {
            return inj;
        }
        inj = injectCurve(prober, privSlot, c);
        if (inj != null) {
            return inj;
        }
        if (mode == KeyMode.GEN) {
            var gen = prober.genKeyPair(pubSlot, privSlot);
            if (!gen.ok()) {
                return Step.skip("genKeyPair %s".formatted(exc(gen)));
            }
            return null;
        }
        var host = hostEcPair(c);
        var es = set(prober, privSlot, CryptoProber.COMP_S, host.s());
        if (es != null) {
            return es;
        }
        return set(prober, pubSlot, CryptoProber.COMP_W, host.w());
    }

    // Host-side EC keypair at canonical widths: the private scalar S unsigned, the public point W
    // uncompressed. The seeded RNG makes the pair reproducible across runs and groups.
    private record HostEc(byte[] s, byte[] w) {
    }

    private static HostEc hostEcPair(Curve c) {
        var kpg = new ECKeyPairGenerator();
        kpg.init(new ECKeyGenerationParameters(c.dom(), seeded()));
        var kp = kpg.generateKeyPair();
        var s = unsigned(((ECPrivateKeyParameters) kp.getPrivate()).getD());
        var w = ((ECPublicKeyParameters) kp.getPublic()).getQ().getEncoded(false);
        return new HostEc(s, w);
    }

    // Sends the curve parameters at their canonical widths and reports whatever the card does:
    // field elements (p, a, b) at the field width, the order at its own byte length, the generator
    // uncompressed. No probing of slot widths and no adapting to them - a card that refuses a
    // parameter is reported as a skip carrying its CryptoException reason, never pre-judged here.
    private Step injectCurve(CryptoProber prober, int slot, Curve c) {
        for (Comp comp : domainComps(c, slot)) {
            var err = set(prober, slot, comp.id(), comp.expected());
            if (err != null) {
                return err;
            }
        }
        return null;
    }

    // The six EC domain parameters in injection order, each at its canonical width: field elements
    // (p, a, b) at the field width, the generator uncompressed, the order at its own byte length.
    private static List<Comp> domainComps(Curve c, int slot) {
        int fb = c.fieldBytes();
        int h = c.x9().getH().intValueExact();
        return List.of(
                new Comp(slot, CryptoProber.COMP_FIELD_FP, "field", fixed(c.x9().getCurve().getField().getCharacteristic(), fb)),
                new Comp(slot, CryptoProber.COMP_A, "A", fixed(c.x9().getCurve().getA().toBigInteger(), fb)),
                new Comp(slot, CryptoProber.COMP_B, "B", fixed(c.x9().getCurve().getB().toBigInteger(), fb)),
                new Comp(slot, CryptoProber.COMP_G, "G", c.x9().getG().getEncoded(false)),
                new Comp(slot, CryptoProber.COMP_R, "R", unsigned(c.x9().getN())),
                new Comp(slot, CryptoProber.COMP_K, "K", new byte[]{(byte) (h >> 8), (byte) h}));
    }

    private Step set(CryptoProber prober, int slot, int compId, byte[] data) {
        var r = prober.setComponent(slot, compId, data);
        if (!r.ok()) {
            return Step.skip("setComponent %d %s".formatted(compId, exc(r)));
        }
        return null;
    }

    // Component read-out fidelity. Sets every EC component to a known canonical value (domain at its
    // SEC encoding, host-generated S and W) and reads each back, reporting per curve whether the
    // getter returns the exact bytes that went in. Pure reporting across backends - whether a width
    // difference is acceptable is left to whoever reads the output.
    private record Comp(int slot, int id, String name, byte[] expected) {
    }

    private void runComponentReadback(CryptoProber prober) {
        runGroup("READBACK", List.of(PRIME_CURVES), cn -> readbackCase(prober, cn));
    }

    private Outcome readbackCase(CryptoProber prober, String cn) {
        var c = curve(cn);
        var pub = prober.newKey(SLOT_PUB_A, 0, KeyBuilder.TYPE_EC_FP_PUBLIC, c.fieldBits());
        var priv = prober.newKey(SLOT_PRIV_A, 0, KeyBuilder.TYPE_EC_FP_PRIVATE, c.fieldBits());
        if (!pub.ok() || !priv.ok()) {
            return new Skip("READBACK skip " + cn + " : buildKey " + exc(pub.ok() ? priv : pub));
        }
        var inj = injectCurve(prober, SLOT_PRIV_A, c);
        if (inj == null) {
            inj = injectCurve(prober, SLOT_PUB_A, c);
        }
        if (inj != null) {
            return new Skip("READBACK skip " + cn + " : " + inj.reason());
        }
        var host = hostEcPair(c);
        if (set(prober, SLOT_PRIV_A, CryptoProber.COMP_S, host.s()) != null
                || set(prober, SLOT_PUB_A, CryptoProber.COMP_W, host.w()) != null) {
            return new Skip("READBACK skip " + cn + " : set S/W rejected");
        }
        var comps = new ArrayList<>(domainComps(c, SLOT_PRIV_A));
        comps.add(new Comp(SLOT_PRIV_A, CryptoProber.COMP_S, "S", host.s()));
        comps.add(new Comp(SLOT_PUB_A, CryptoProber.COMP_W, "W", host.w()));
        var diffs = new ArrayList<String>();
        for (Comp comp : comps) {
            var got = prober.getComponent(comp.slot(), comp.id());
            if (!got.ok()) {
                diffs.add("%s get %s".formatted(comp.name(), exc(got)));
            } else if (!Arrays.equals(comp.expected(), got.output())) {
                diffs.add("%s set=%s got=%s".formatted(comp.name(), HexUtils.bin2hex(comp.expected()), HexUtils.bin2hex(got.output())));
            }
        }
        if (diffs.isEmpty()) {
            return new Pass("READBACK " + cn + " ok all components 1:1");
        }
        return new Fail("READBACK " + cn + " : " + String.join("; ", diffs));
    }

    // ECDSA

    private static List<Alg> ecdsaAlgs() {
        return List.of(
                new Alg(Signature.ALG_ECDSA_SHA, "ECDSA-SHA1", new SHA1Digest()),
                new Alg(Signature.ALG_ECDSA_SHA_224, "ECDSA-SHA224", new SHA224Digest()),
                new Alg(Signature.ALG_ECDSA_SHA_256, "ECDSA-SHA256", new SHA256Digest()),
                new Alg(Signature.ALG_ECDSA_SHA_384, "ECDSA-SHA384", new SHA384Digest()),
                new Alg(Signature.ALG_ECDSA_SHA_512, "ECDSA-SHA512", new SHA512Digest()));
    }

    private void runEcdsa(CryptoProber prober) {
        runGroupMulti("ECDSA", List.of(PRIME_CURVES), cn -> {
            var c = curve(cn);
            var out = new ArrayList<Outcome>();
            for (KeyMode mode : KeyMode.values()) {
                var built = buildEcKeyPair(prober, c, SLOT_PUB_A, SLOT_PRIV_A, mode);
                if (built != null) {
                    out.add(labeled("ECDSA", cn + "/" + mode, built));
                    continue;
                }
                var bcPub = readBcPub(prober, c, SLOT_PUB_A);
                var bcPriv = readBcPriv(prober, c, SLOT_PRIV_A);
                for (var alg : ecdsaAlgs()) {
                    out.add(runEcdsaCase(prober, c, alg, bcPub, bcPriv, mode));
                }
            }
            return out;
        });
    }

    private Outcome runEcdsaCase(CryptoProber prober, Curve c, Alg alg, ECPublicKeyParameters bcPub, ECPrivateKeyParameters bcPriv, KeyMode mode) {
        String tag = c.name() + "/" + mode + "/" + alg.name();
        byte[] hash = digest(alg.bc(), INPUT);

        // card signs, BC verifies
        var sig = prober.sign(alg.id(), SLOT_PRIV_A, INPUT);
        if (!sig.ok()) {
            return new Fail("ECDSA %s sign %s".formatted(tag, exc(sig)));
        }
        var rs = decodeDer(sig.output());
        var verifier = new ECDSASigner();
        verifier.init(false, bcPub);
        if (!verifier.verifySignature(hash, rs[0], rs[1])) {
            return new Fail("ECDSA %s engine-sign not verified by BC; sig=%s".formatted(tag, HexUtils.bin2hex(sig.output())));
        }

        // BC signs, card verifies; retCode carries the card's verify() result
        var bcSigner = new ECDSASigner();
        bcSigner.init(true, new ParametersWithRandom(bcPriv, seeded()));
        var bcRs = bcSigner.generateSignature(hash);
        var bcDer = encodeDer(bcRs[0], bcRs[1]);
        var vr = prober.verify(alg.id(), SLOT_PUB_A, bcDer, INPUT);
        if (!vr.ok()) {
            return new Fail("ECDSA %s verify %s".formatted(tag, exc(vr)));
        }
        if (vr.retCode() != 1) {
            return new Fail("ECDSA %s BC-sign not verified by engine (retCode=%d); sig=%s".formatted(tag, vr.retCode(), HexUtils.bin2hex(bcDer)));
        }

        // card verifies its own signature; catches sign/verify asymmetries (non-canonical S, odd
        // DER length) that BC's lenient verifier would accept
        var self = prober.verify(alg.id(), SLOT_PUB_A, sig.output(), INPUT);
        if (!self.ok()) {
            return new Fail("ECDSA %s self-verify %s".formatted(tag, exc(self)));
        }
        if (self.retCode() != 1) {
            return new Fail("ECDSA %s card did not verify its own signature; sig=%s".formatted(tag, HexUtils.bin2hex(sig.output())));
        }
        return new Pass("ECDSA %s ok card-sig-len=%d both directions + self verify".formatted(tag, sig.output().length));
    }

    private ECPublicKeyParameters readBcPub(CryptoProber prober, Curve c, int pubSlot) {
        var w = prober.getComponent(pubSlot, CryptoProber.COMP_W);
        var q = c.x9().getCurve().decodePoint(w.output());
        return new ECPublicKeyParameters(q, c.dom());
    }

    private ECPrivateKeyParameters readBcPriv(CryptoProber prober, Curve c, int privSlot) {
        var s = prober.getComponent(privSlot, CryptoProber.COMP_S);
        var d = new BigInteger(1, s.output());
        return new ECPrivateKeyParameters(d, c.dom());
    }

    // ECDH

    private void runEcdh(CryptoProber prober) {
        runGroup("ECDH", List.of(PRIME_CURVES), cn -> {
            var c = curve(cn);
            var a = buildEcKeyPair(prober, c, SLOT_PUB_A, SLOT_PRIV_A, KeyMode.GEN);
            if (a != null) {
                return labeled("ECDH", cn, a);
            }
            var b = buildEcKeyPair(prober, c, SLOT_PUB_B, SLOT_PRIV_B, KeyMode.GEN);
            if (b != null) {
                return labeled("ECDH", cn, b);
            }
            return runEcdhCase(prober, c);
        });
    }

    private Outcome runEcdhCase(CryptoProber prober, Curve c) {
        var wB = prober.getComponent(SLOT_PUB_B, CryptoProber.COMP_W);
        var ka = prober.keyAgreement(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, SLOT_PRIV_A, wB.output());
        if (!ka.ok()) {
            return new Fail("ECDH %s %s".formatted(c.name(), exc(ka)));
        }
        var dA = readBcPriv(prober, c, SLOT_PRIV_A);
        var qB = c.x9().getCurve().decodePoint(wB.output());
        var agree = new ECDHBasicAgreement();
        agree.init(dA);
        var z = agree.calculateAgreement(new ECPublicKeyParameters(qB, c.dom()));
        byte[] bcSecret = fixed(z, c.fieldBytes());
        if (!Arrays.equals(bcSecret, ka.output())) {
            return new Fail("ECDH %s engine=%s bc=%s".formatted(c.name(), HexUtils.bin2hex(ka.output()), HexUtils.bin2hex(bcSecret)));
        }
        return new Pass("ECDH %s ok secret-len=%d card==BC".formatted(c.name(), ka.output().length));
    }

    // RSA

    private enum RsaKey {PLAIN, CRT}

    private record RsaPad(byte alg, String name) {}

    // EXP_4BYTE (0xFFFFFFFB = 2^32-5, prime, high bit set) fills a 4-byte exponent and forces the
    // unsigned-encoding strip that BigInteger.toByteArray() needs for values with the high bit set.
    private static final long EXP_F4 = 0x10001L;
    private static final long EXP_4BYTE = 0xFFFFFFFBL;

    private static final int[] RSA_SIZES = {512, 736, 768, 896, 1024, 1280, 1536, 1984, 2048, 3072, 4096};

    private record RsaCase(int bits, KeyMode mode, RsaKey form, long e) {
        String tag() {
            return "%d/%s/%s/e=%X".formatted(bits, mode, form, e);
        }
    }

    private static List<RsaPad> rsaPaddings() {
        return List.of(new RsaPad(Cipher.ALG_RSA_PKCS1, "PKCS1"), new RsaPad(Cipher.ALG_RSA_PKCS1_OAEP, "OAEP"));
    }

    private static List<RsaCase> rsaCases(int bits) {
        return List.of(
                new RsaCase(bits, KeyMode.INJECT, RsaKey.PLAIN, EXP_F4),
                new RsaCase(bits, KeyMode.INJECT, RsaKey.CRT, EXP_F4),
                new RsaCase(bits, KeyMode.INJECT, RsaKey.CRT, EXP_4BYTE),
                new RsaCase(bits, KeyMode.GEN, RsaKey.CRT, EXP_F4));
    }

    // Tests only the smallest and largest RSA key size the card accepts. Intermediate sizes are not
    // exercised; deliberate, to keep the run short enough on real silicon.
    private void runRsa(CryptoProber prober) {
        int max = supportedSize(prober, false);
        int min = supportedSize(prober, true);
        if (max < 0) {
            System.out.println("RSA skip : card builds no RSA key size");
            summary("RSA", 0, 1, List.of());
            return;
        }
        var sizes = min == max ? List.of(min) : List.of(min, max);
        var cases = sizes.stream().flatMap(bits -> rsaCases(bits).stream()).toList();
        runGroup("RSA", cases, rc -> runRsaCase(prober, rc));
    }

    // Returns the smallest (ascending=true) or largest (ascending=false) RSA key size the card builds
    // successfully for both public and private, or -1 if none.
    private static int supportedSize(CryptoProber prober, boolean ascending) {
        for (int i = 0; i < RSA_SIZES.length; i++) {
            int bits = RSA_SIZES[ascending ? i : RSA_SIZES.length - 1 - i];
            if (prober.newKey(SLOT_RSA_PUB, 0, KeyBuilder.TYPE_RSA_PUBLIC, bits).ok()
                    && prober.newKey(SLOT_RSA_PRIV, 0, KeyBuilder.TYPE_RSA_PRIVATE, bits).ok()) {
                return bits;
            }
        }
        return -1;
    }

    private Outcome runRsaCase(CryptoProber prober, RsaCase rc) {
        return rc.mode() == KeyMode.GEN ? runRsaGen(prober, rc) : runRsaInject(prober, rc);
    }

    // Loads a host-generated keypair component-by-component, then cross-checks both directions of
    // each padding scheme against BC.
    private Outcome runRsaInject(CryptoProber prober, RsaCase rc) {
        int bits = rc.bits();
        int modBytes = bits / 8;
        var gen = new RSAKeyPairGenerator();
        gen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(rc.e()), seeded(), bits, 80));
        var kp = gen.generateKeyPair();
        var pub = (RSAKeyParameters) kp.getPublic();
        var priv = (RSAKeyParameters) kp.getPrivate();
        var mod = fixed(pub.getModulus(), modBytes);

        var pubKey = prober.newKey(SLOT_RSA_PUB, 0, KeyBuilder.TYPE_RSA_PUBLIC, bits);
        if (!pubKey.ok()) {
            return new Skip("RSA skip %s : buildKey RSA public %s".formatted(rc.tag(), exc(pubKey)));
        }
        var sm = prober.setComponent(SLOT_RSA_PUB, CryptoProber.COMP_RSA_MOD, mod);
        if (!sm.ok()) {
            return new Fail("RSA %s setModulus pub %s".formatted(rc.tag(), exc(sm)));
        }
        var se = prober.setComponent(SLOT_RSA_PUB, CryptoProber.COMP_RSA_EXP, unsigned(pub.getExponent()));
        if (!se.ok()) {
            return new Fail("RSA %s setExponent %s".formatted(rc.tag(), exc(se)));
        }
        var privErr = rc.form() == RsaKey.PLAIN
                ? injectPlainPrivate(prober, rc, priv, modBytes, mod)
                : injectCrtPrivate(prober, rc, (RSAPrivateCrtKeyParameters) kp.getPrivate(), modBytes);
        if (privErr != null) {
            return labeled("RSA", rc.tag(), privErr);
        }

        // ALG_RSA_NOPAD is deterministic: card ciphertext must match BC byte-for-byte, and the
        // decrypted output must be full modulus width with leading zeros intact.
        byte[] block = rsaBlock(modBytes);
        byte[] bcCt = rsaRaw(pub, block);
        var rawEnc = prober.cipher(Cipher.ALG_RSA_NOPAD, CryptoProber.MODE_ENCRYPT, SLOT_RSA_PUB, null, block);
        if (rawEnc.noSuchAlgorithm()) {
            return new Skip("RSA skip %s : RSA_NOPAD NO_SUCH_ALGORITHM".formatted(rc.tag()));
        }
        if (!rawEnc.ok()) {
            return new Fail("RSA %s NOPAD enc %s".formatted(rc.tag(), exc(rawEnc)));
        }
        if (!Arrays.equals(bcCt, rawEnc.output())) {
            return new Fail("RSA %s NOPAD enc format card=%s bc=%s".formatted(rc.tag(), HexUtils.bin2hex(rawEnc.output()), HexUtils.bin2hex(bcCt)));
        }
        var nopad = rsaNopadDecRoundtrip(prober, rc, pub, block);
        if (nopad != null) {
            return nopad;
        }

        byte[] msg = rsaMsg(modBytes);
        for (var p : rsaPaddings()) {
            var enc = prober.cipher(p.alg(), CryptoProber.MODE_ENCRYPT, SLOT_RSA_PUB, null, msg);
            if (enc.noSuchAlgorithm()) {
                System.out.println("RSA skip " + rc.tag() + "/" + p.name() + " : NO_SUCH_ALGORITHM");
                continue;
            }
            if (!enc.ok()) {
                return new Fail("RSA %s %s enc %s".formatted(rc.tag(), p.name(), exc(enc)));
            }
            if (!Arrays.equals(msg, bcRsa(p.alg(), priv, enc.output(), false))) {
                return new Fail("RSA %s %s card-enc/BC-dec did not recover".formatted(rc.tag(), p.name()));
            }
        }
        var padded = rsaPaddingDecLoop(prober, rc, pub, msg);
        if (padded != null) {
            return padded;
        }
        return new Pass("RSA %s ok both directions recover".formatted(rc.tag()));
    }

    // Card generates a CRT keypair; the public half is read back for BC. Only BC-encrypt/card-decrypt
    // is checked; card-encrypt cannot be verified without exporting the private key.
    private Outcome runRsaGen(CryptoProber prober, RsaCase rc) {
        int bits = rc.bits();
        int modBytes = bits / 8;
        var pubKey = prober.newKey(SLOT_RSA_PUB, 0, KeyBuilder.TYPE_RSA_PUBLIC, bits);
        if (!pubKey.ok()) {
            return new Skip("RSA skip %s : buildKey RSA public %s".formatted(rc.tag(), exc(pubKey)));
        }
        var privKey = prober.newKey(SLOT_RSA_PRIV, 0, KeyBuilder.TYPE_RSA_CRT_PRIVATE, bits);
        if (!privKey.ok()) {
            return new Skip("RSA skip %s : buildKey RSA CRT private %s".formatted(rc.tag(), exc(privKey)));
        }
        var gen = prober.genKeyPair(SLOT_RSA_PUB, SLOT_RSA_PRIV);
        if (!gen.ok()) {
            return new Skip("RSA skip %s : genKeyPair RSA %s".formatted(rc.tag(), exc(gen)));
        }
        var rm = prober.getComponent(SLOT_RSA_PUB, CryptoProber.COMP_RSA_MOD);
        var re = prober.getComponent(SLOT_RSA_PUB, CryptoProber.COMP_RSA_EXP);
        if (!rm.ok() || !re.ok()) {
            return new Fail("RSA %s read generated public %s".formatted(rc.tag(), exc(rm.ok() ? re : rm)));
        }
        var pub = new RSAKeyParameters(false, new BigInteger(1, rm.output()), new BigInteger(1, re.output()));

        // Card applies the raw RSA private transform; host verifies with the extracted public key
        // and checks output width == modulus width.
        byte[] block = rsaBlock(modBytes);
        var cardSig = prober.cipher(Cipher.ALG_RSA_NOPAD, CryptoProber.MODE_DECRYPT, SLOT_RSA_PRIV, null, block);
        if (cardSig.noSuchAlgorithm()) {
            return new Skip("RSA skip %s : RSA_NOPAD NO_SUCH_ALGORITHM".formatted(rc.tag()));
        }
        if (!cardSig.ok()) {
            return new Fail("RSA %s NOPAD sign %s".formatted(rc.tag(), exc(cardSig)));
        }
        if (cardSig.output().length != modBytes) {
            return new Fail("RSA %s NOPAD card-sign width=%d want=%d".formatted(rc.tag(), cardSig.output().length, modBytes));
        }
        if (!Arrays.equals(block, rsaRaw(pub, cardSig.output()))) {
            return new Fail("RSA %s NOPAD card-sign not recovered by host pubkey; sig=%s".formatted(rc.tag(), HexUtils.bin2hex(cardSig.output())));
        }
        var nopad = rsaNopadDecRoundtrip(prober, rc, pub, block);
        if (nopad != null) {
            return nopad;
        }
        byte[] msg = rsaMsg(modBytes);
        var padded = rsaPaddingDecLoop(prober, rc, pub, msg);
        if (padded != null) {
            return padded;
        }
        return new Pass("RSA %s gen ok: card-sign verified by host pubkey, padded host-enc/card-dec".formatted(rc.tag()));
    }

    // Card decrypts a host-sealed raw block; output must be the original block at full modulus width
    // with leading zeros intact. Returns a terminal Outcome on rejection, null to continue.
    private Outcome rsaNopadDecRoundtrip(CryptoProber prober, RsaCase rc, RSAKeyParameters pub, byte[] block) {
        var rawDec = prober.cipher(Cipher.ALG_RSA_NOPAD, CryptoProber.MODE_DECRYPT, SLOT_RSA_PRIV, null, rsaRaw(pub, block));
        if (!rawDec.ok()) {
            return new Fail("RSA %s NOPAD dec %s".formatted(rc.tag(), exc(rawDec)));
        }
        if (!Arrays.equals(block, rawDec.output())) {
            return new Fail("RSA %s NOPAD dec format card=%s want=%s".formatted(rc.tag(), HexUtils.bin2hex(rawDec.output()), HexUtils.bin2hex(block)));
        }
        return null;
    }

    // For each padding scheme, the card decrypts a BC-sealed message and must recover it. A scheme
    // the card lacks is skipped. Returns a terminal Outcome on rejection, null to continue.
    private Outcome rsaPaddingDecLoop(CryptoProber prober, RsaCase rc, RSAKeyParameters pub, byte[] msg) {
        for (var p : rsaPaddings()) {
            var dec = prober.cipher(p.alg(), CryptoProber.MODE_DECRYPT, SLOT_RSA_PRIV, null, bcRsa(p.alg(), pub, msg, true));
            if (dec.noSuchAlgorithm()) {
                System.out.println("RSA skip " + rc.tag() + "/" + p.name() + " : NO_SUCH_ALGORITHM");
                continue;
            }
            if (!dec.ok()) {
                return new Fail("RSA %s %s dec %s".formatted(rc.tag(), p.name(), exc(dec)));
            }
            if (!Arrays.equals(msg, dec.output())) {
                return new Fail("RSA %s %s BC-enc/card-dec did not recover got=%s".formatted(rc.tag(), p.name(), HexUtils.bin2hex(dec.output())));
            }
        }
        return null;
    }

    private Step injectPlainPrivate(CryptoProber prober, RsaCase rc, RSAKeyParameters priv, int modBytes, byte[] mod) {
        var privKey = prober.newKey(SLOT_RSA_PRIV, 0, KeyBuilder.TYPE_RSA_PRIVATE, rc.bits());
        if (!privKey.ok()) {
            return Step.skip("buildKey RSA private %s".formatted(exc(privKey)));
        }
        var sm = prober.setComponent(SLOT_RSA_PRIV, CryptoProber.COMP_RSA_MOD, mod);
        if (!sm.ok()) {
            return Step.fail("setModulus priv %s".formatted(exc(sm)));
        }
        var sd = prober.setComponent(SLOT_RSA_PRIV, CryptoProber.COMP_RSA_PRIVEXP, fixed(priv.getExponent(), modBytes));
        if (!sd.ok()) {
            return Step.fail("setPrivExp %s".formatted(exc(sd)));
        }
        return null;
    }

    // CRT components: P, Q, DP1=d mod (p-1), DQ1=d mod (q-1), PQ=q^-1 mod p, each half the modulus
    // width. RSAPrivateCrtKeyParameters exposes exactly these fields.
    private Step injectCrtPrivate(CryptoProber prober, RsaCase rc, RSAPrivateCrtKeyParameters crt, int modBytes) {
        var privKey = prober.newKey(SLOT_RSA_PRIV, 0, KeyBuilder.TYPE_RSA_CRT_PRIVATE, rc.bits());
        if (!privKey.ok()) {
            return Step.skip("buildKey RSA CRT private %s".formatted(exc(privKey)));
        }
        int half = modBytes / 2;
        int[] ids = {CryptoProber.COMP_P, CryptoProber.COMP_Q, CryptoProber.COMP_DP, CryptoProber.COMP_DQ, CryptoProber.COMP_PQ};
        BigInteger[] vals = {crt.getP(), crt.getQ(), crt.getDP(), crt.getDQ(), crt.getQInv()};
        for (int i = 0; i < ids.length; i++) {
            var err = setPriv(prober, ids[i], fixed(vals[i], half));
            if (err != null) {
                return err;
            }
        }
        return null;
    }

    private static Step setPriv(CryptoProber prober, int compId, byte[] data) {
        var r = prober.setComponent(SLOT_RSA_PRIV, compId, data);
        return r.ok() ? null : Step.fail("setComp %d %s".formatted(compId, exc(r)));
    }

    // SHA-1 OAEP overhead is 2*20+2 = 42 bytes; capped at 32 so the smallest probed key fits.
    private static byte[] rsaMsg(int modBytes) {
        return Arrays.copyOf(INPUT, Math.min(32, modBytes - 42));
    }

    // Leading zero byte keeps the value below the modulus and forces ALG_RSA_NOPAD to return full
    // modulus width (leading zeros preserved), not just the numeric value.
    private static byte[] rsaBlock(int modBytes) {
        byte[] block = new byte[modBytes];
        var rnd = seeded();
        rnd.nextBytes(block);
        block[0] = 0x00;   // forces width check (value < modulus, output must still be modBytes wide)
        block[1] |= 0x01;  // prevent an all-zero block
        return block;
    }

    // BigInteger.toByteArray() prepends 0x00 when the high bit is set; strip it for unsigned encoding.
    private static byte[] unsigned(BigInteger v) {
        byte[] b = v.toByteArray();
        if (b.length > 1 && b[0] == 0) {
            return Arrays.copyOfRange(b, 1, b.length);
        }
        return b;
    }

    private static byte[] rsaRaw(RSAKeyParameters key, byte[] block) {
        var engine = new RSAEngine();
        engine.init(true, key);
        return engine.processBlock(block, 0, block.length);
    }

    private static AsymmetricBlockCipher rsaPaddingEngine(byte alg) {
        if (alg == Cipher.ALG_RSA_PKCS1_OAEP) {
            return new OAEPEncoding(new RSAEngine());
        }
        return new PKCS1Encoding(new RSAEngine());
    }

    // BC reference run of the padded RSA transform, in either direction; encrypt selects init's mode.
    private static byte[] bcRsa(byte alg, RSAKeyParameters key, byte[] in, boolean encrypt) {
        var c = rsaPaddingEngine(alg);
        c.init(encrypt, key);
        try {
            return c.processBlock(in, 0, in.length);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }

    // Helpers

    private static byte[] makeInput() {
        byte[] abc = {(byte) 'a', (byte) 'b', (byte) 'c'};
        byte[] in = new byte[abc.length + 64];
        System.arraycopy(abc, 0, in, 0, abc.length);
        for (int i = 0; i < 64; i++) {
            in[abc.length + i] = (byte) (i * 7 + 1);
        }
        return in;
    }

    // Fixed-seed RNG: every generated keypair, signature, and cipher input is deterministic and
    // reproducible across runs. The INJECT EC keys built in buildEcKeyPair and readbackCase are
    // byte-identical for the same curve as a result.
    private static SecureRandom seeded() {
        var r = new SecureRandom();
        r.setSeed(0x0BADC0DECAFEL);
        return r;
    }

    private static byte[] digest(Digest d, byte[] msg) {
        d.reset();
        d.update(msg, 0, msg.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    private static BigInteger[] decodeDer(byte[] der) {
        ASN1Sequence seq = ASN1Sequence.getInstance(der);
        var r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
        var s = ((ASN1Integer) seq.getObjectAt(1)).getValue();
        return new BigInteger[]{r, s};
    }

    private static byte[] encodeDer(BigInteger r, BigInteger s) {
        var v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        try {
            return new DERSequence(v).getEncoded();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static String exc(Result r) {
        return "exc type=%d reason=%d".formatted(r.excType(), r.reason());
    }

    private static void summary(String label, int passed, int skipped, List<String> failures) {
        System.out.println("%s passed=%d skipped=%d failed=%d".formatted(label, passed, skipped, failures.size()));
        failures.forEach(System.out::println);
    }

    // Per-case verdict. Pass/Skip carry an optional line to print; Fail's message is collected and
    // dumped under the group summary.
    private sealed interface Outcome permits Pass, Skip, Fail {
    }

    private record Pass(String note) implements Outcome {
    }

    private record Skip(String message) implements Outcome {
    }

    private record Fail(String message) implements Outcome {
    }

    // Result of a builder sub-step that did not complete: skip if the card refused (fail=false),
    // fail if the card rejected well-formed input (fail=true). The reason is context-free; the
    // case runner that observes it labels it into a Skip or Fail line.
    private record Step(boolean fail, String reason) {
        static Step skip(String reason) {
            return new Step(false, reason);
        }

        static Step fail(String reason) {
            return new Step(true, reason);
        }
    }

    // Labels a builder Step into a display line: a fail Step becomes a Fail, a refusal becomes a Skip.
    // The label and tag are prepended uniformly; the Step's reason carries only the distinguishing
    // detail, so the skip/fail word comes from Step, never from the call site.
    private static Outcome labeled(String label, String tag, Step step) {
        return step.fail()
                ? new Fail("%s %s : %s".formatted(label, tag, step.reason()))
                : new Skip("%s skip %s : %s".formatted(label, tag, step.reason()));
    }

    // Tallies one verdict per item.
    private static <T> void runGroup(String label, List<T> items, Function<T, Outcome> fn) {
        runGroupMulti(label, items, item -> List.of(fn.apply(item)));
    }

    // Tallies several verdicts per item, for groups that fan one case out over sub-variants.
    private static <T> void runGroupMulti(String label, List<T> items, Function<T, List<Outcome>> fn) {
        int passed = 0;
        int skipped = 0;
        var failures = new ArrayList<String>();
        for (T item : items) {
            for (Outcome o : fn.apply(item)) {
                if (o instanceof Pass p) {
                    passed++;
                    if (p.note() != null) {
                        System.out.println(p.note());
                    }
                } else if (o instanceof Skip s) {
                    skipped++;
                    System.out.println(s.message());
                } else if (o instanceof Fail f) {
                    failures.add(f.message());
                }
            }
        }
        summary(label, passed, skipped, failures);
    }

}
