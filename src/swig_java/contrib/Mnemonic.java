package com.blockstream.libwally;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static com.blockstream.libwally.wallycore.BIP39_ENTROPY_LEN_256;
import static com.blockstream.libwally.wallycore.BIP39_SEED_LEN_512;

public class Mnemonic {

    private final SecureRandom sr = new SecureRandom();
    private final wallycore.Obj wl;

    public Mnemonic(final String lang) {
        this.wl = wallycore.bip39_get_wordlist(lang);
    }

    public static String[] getLanguages() {
        return wallycore.bip39_get_languages().split(" ");
    }

    public String generate(final int strength) {
        final byte[] seed = new byte[strength];
        sr.nextBytes(seed);
        return toMnemonic(seed);
    }

    public String generate() {
        return generate(BIP39_ENTROPY_LEN_256);
    }

    public byte[] toEntropy(final String mnemonics) {
        final byte[] buf = new byte[BIP39_ENTROPY_LEN_256];
        return Arrays.copyOf(buf, wallycore.bip39_mnemonic_to_bytes(
                wl, mnemonics, buf));
    }

    public String toMnemonic(final byte[] data) {
        return wallycore.bip39_mnemonic_from_bytes(wl, data);
    }

    public boolean check(final String mnemonic) {
        try {
            wallycore.bip39_mnemonic_validate(wl, mnemonic);
            return true;
        } catch (final Exception e) {
            return false;
        }
    }

    public byte[] toSeed(final String mnemonic, final String passphrase) {
        final byte[] buf = new byte[BIP39_SEED_LEN_512];
        wallycore.bip39_mnemonic_to_seed(mnemonic, passphrase, buf);
        return buf;
    }

    private static final Map<String, byte[]> testMap;
    static {
        final String m =
                "legal winner thank year wave sausage worth useful legal winner thank yellow";
        final Map<String, byte[]> aMap = new HashMap<>();
        aMap.put(m, new byte[]{});
        aMap.put(m, null);
        aMap.put("gibberish", new byte[BIP39_ENTROPY_LEN_256]);
        aMap.put("", new byte[BIP39_ENTROPY_LEN_256]);
        aMap.put(null, new byte[BIP39_ENTROPY_LEN_256]);
        testMap = Collections.unmodifiableMap(aMap);
    }
    public static void main(final String[] args) {
        for (final String lang : getLanguages()) {
            final Mnemonic m = new Mnemonic(lang);
            final String phrase = m.generate();
            if (!m.check(phrase) ||
                m.check(String.format("%s foo", phrase)) ||
                !Arrays.equals(m.toEntropy(phrase), m.toEntropy(phrase)) ||
                !m.toMnemonic(m.toEntropy(phrase)).equals(phrase) ||
                Arrays.equals(m.toSeed(phrase, "foo"), m.toSeed(phrase, "bar")))
                throw new RuntimeException("Mnemonic failed basic verification");
        }

        for(final Map.Entry<String, byte[]> entry : testMap.entrySet())
            try {
                wallycore.bip39_mnemonic_to_bytes(null, entry.getKey(), entry.getValue());
                throw new RuntimeException("Mnemonic failed basic verification");
            } catch (final IllegalArgumentException e) {
                // pass
            }
        final byte[] data = new byte[BIP39_ENTROPY_LEN_256];

        try {
            wallycore.bip39_mnemonic_from_bytes(null, data);
            throw new RuntimeException("Mnemonic failed basic verification");
        } catch (final IllegalArgumentException e) {
            // pass
        }

        try {
            wallycore.bip39_mnemonic_from_bytes((wallycore.Obj)new Object(), data);
            throw new RuntimeException("Mnemonic failed basic verification");
        } catch (final ClassCastException e) {
            // pass
        }
    }
}
