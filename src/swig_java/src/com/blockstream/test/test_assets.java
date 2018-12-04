package com.blockstream.test;

import com.blockstream.libwally.Wally;

public class test_assets {

    static final String ONES = "1111111111111111111111111111111111111111111111111111111111111111";
    static final String TWOS = "2222222222222222222222222222222222222222222222222222222222222222";

    public test_assets() { }

    public void test_blinding() {

        final byte[] asset = h(ONES);
        final byte[] abf = h(ONES);
        final byte[] generator = Wally.asset_generator_from_bytes(asset, abf);

        final long[] values = new long[] { 20000, 4910, 13990, 1100 };
        final byte[] last_vbf = Wally.asset_final_vbf(values, 1,
                        h("7fca161c2b849a434f49065cf590f5f1909f25e252f728dfd53669c3c8f8e37100000000000000000000000000000000000000000000000000000000000000002c89075f3c8861fea27a15682d664fb643bc08598fe36dcf817fcabc7ef5cf2efdac7bbad99a45187f863cd58686a75135f2cc0714052f809b0c1f603bcdc574"),
                        h("1c07611b193009e847e5b296f05a561c559ca84e16d1edae6cbe914b73fb6904000000000000000000000000000000000000000000000000000000000000000074e4135177cd281b332bb8fceb46da32abda5d6dc4d2eef6342a5399c9fb3c48"));
        if (!h(last_vbf).equals("6996212c70fa85b82d4fd76bd262e0cebc5d8f52350a73af8d2b881a30442b9d"))
            throw new RuntimeException("Unexpected asset_final_vbf result");
    }

    private void test_confidential_address() {
        final String addr = "Q7qcjTLsYGoMA7TjUp97R6E6AM5VKqBik6";
        final String pubkey_hex = "02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623";
        final String addr_c = "VTpz1bNuCALgavJKgbAw9Lpp9A72rJy64XPqgqfnaLpMjRcPh5UHBqyRUE4WMZ3asjqu7YEPVAnWw2EK";

        final String new_addr = Wally.confidential_addr_to_addr(addr_c, Wally.WALLY_CA_PREFIX_LIQUID);
        if (!new_addr.equals(addr))
            throw new RuntimeException("Failed to extract address from confidential address");

        final byte[] pubkey = Wally.confidential_addr_to_ec_public_key(addr_c, Wally.WALLY_CA_PREFIX_LIQUID);
        if (!Wally.hex_from_bytes(pubkey).equals(pubkey_hex))
            throw new RuntimeException("Failed to extract pubkey from confidential address");

        final String new_addr_c = Wally.confidential_addr_from_addr(addr, Wally.WALLY_CA_PREFIX_LIQUID, pubkey);
        if (!new_addr_c.equals(addr_c))
            throw new RuntimeException("Failed to create confidential address");
    }

    private String h(final byte[] bytes) { return Wally.hex_from_bytes(bytes); }
    private byte[] h(final String hex) { return Wally.hex_to_bytes(hex); }

    public static void main(final String[] args) {
        final test_assets t = new test_assets();
        t.test_blinding();
        t.test_confidential_address();
    }
}
