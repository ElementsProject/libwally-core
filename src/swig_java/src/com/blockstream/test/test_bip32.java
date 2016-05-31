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
    }

    public static void main(final String[] args) {
        final test_bip32 t = new test_bip32();
        t.test();

        //throw new RuntimeException("Failed");
    }
}
