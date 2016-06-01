package com.blockstream.test;

import com.blockstream.libwally.Wally;
import static com.blockstream.libwally.Wally.BIP32_KEY_PRIVATE;
import static com.blockstream.libwally.Wally.BIP32_VER_MAIN_PRIVATE;

public class test_bip32 {

    final byte[] mSeed;

    public test_bip32() {
        mSeed = Wally.hex_to_bytes("000102030405060708090a0b0c0d0e0f");
    }

    public void test() {
        final Object seedKey = Wally.bip32_key_from_seed(mSeed, BIP32_VER_MAIN_PRIVATE);
        Wally.bip32_key_free(seedKey);

        final String hex = "0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55" +
            "a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817c" +
            "db01a1494b917c8436b35";
        final byte[] serialized = Wally.hex_to_bytes(hex);
        final Object unserialized = Wally.bip32_key_unserialize(serialized);

        final byte[] newSerialized = Wally.bip32_key_serialize(unserialized, BIP32_KEY_PRIVATE);
        final String newHex = Wally.hex_from_bytes(newSerialized);
        if (!newHex.equals(hex))
            throw new RuntimeException("BIP32 serialization did not round-trip correctly");

        Wally.bip32_key_free(unserialized);
    }

    public static void main(final String[] args) {
        final test_bip32 t = new test_bip32();
        t.test();
    }
}
