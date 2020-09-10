package com.blockstream.test;

import com.blockstream.libwally.Wally;

public class test_descriptor {

    static final String descriptor = "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))#t2zpj2eu";
    final String expected_addrs[] = { "bc1qvjtfmrxu524qhdevl6yyyasjs7xmnzjlqlu60mrwepact60eyz9s9xjw0c",
                                      "bc1qp6rfclasvmwys7w7j4svgc2mrujq9m73s5shpw4e799hwkdcqlcsj464fw",
                                      "bc1qsflxzyj2f2evshspl9n5n745swcvs5k7p5t8qdww5unxpjwdvw5qx53ms4" };

    public test_descriptor() { }

    public static void assert_eq(final Object expected, final Object actual, final String message) {
        if(!expected.equals(actual)) {
            System.out.println(expected);
            System.out.println(actual);
            throw new RuntimeException(message);
        }
    }

    public void test_descriptor_to_addresses() {
        final int child_num = 0;
        final int flags = 0;
        final String[] addrs = Wally.descriptor_to_addresses(descriptor, Wally.map_init(0), child_num,
                                                             Wally.WALLY_NETWORK_BITCOIN_MAINNET, flags,
                                                             expected_addrs.length);

        assert_eq(expected_addrs.length, addrs.length, "Addresses size mismatch");
        for (int i = 0; i < expected_addrs.length; i++) {
            assert_eq(expected_addrs[i], addrs[i], "Addresses mismatch");
        }

        Wally.cleanup();
    }

    public static void main(final String[] args) {
        final test_descriptor t = new test_descriptor();
        t.test_descriptor_to_addresses();
    }
}
