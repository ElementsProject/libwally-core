package com.blockstream.test;

import com.blockstream.libwally.Wally;
import static com.blockstream.libwally.Wally.BIP32_VER_MAIN_PRIVATE;

public class test_bip32 {

    final byte[] mSeed;

    public test_bip32() {
        mSeed = Wally.hex_to_bytes("000102030405060708090a0b0c0d0e0f");
    }

    public void test() {
        final Object seedKey = Wally.bip32_key_from_seed(mSeed, BIP32_VER_MAIN_PRIVATE);
        Wally.bip32_key_free(seedKey);

        final String hex = "0488ADE4000000000000000000873DFF81C02F525623FD1FE5167EAC3A55" +
            "A049DE3D314BB42EE227FFED37D50800E8F32E723DECF4051AEFAC8E2C93C9C5B214313817C" +
            "DB01A1494B917C8436B35";
        final byte[] serialized = Wally.hex_to_bytes(hex);
        final Object unserialized = Wally.bip32_key_unserialize(serialized);
        Wally.bip32_key_free(unserialized);
    }

    public static void main(final String[] args) {
        final test_bip32 t = new test_bip32();
        t.test();
    }
}
