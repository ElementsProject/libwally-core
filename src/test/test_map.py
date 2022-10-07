import unittest
from util import *
from test_bip32 import get_test_master_key, vec_1

BIP32_LEN = 78 # BIP32_SERIALIZED_LEN
FLAG_KEY_PUBLIC = 0x1

class MapTests(unittest.TestCase):

    def test_map(self):
        """Test map functions"""
        m = pointer(wally_map())
        # Test keys. Once sorted we expect order k3, k2, k1
        empty, empty_len = None, 0
        key1, key1_len = make_cbuffer('505050')
        key2, key2_len = make_cbuffer('40404040')
        key3, key3_len = make_cbuffer('404040')
        key4, key4_len = make_cbuffer('6060606060')
        val, val_len = make_cbuffer('ff'*64)
        out, out_len = make_cbuffer('00'*128)

        # Check invalid args
        self.assertEqual(wally_map_init_alloc(0, None, None), WALLY_EINVAL)
        self.assertEqual(wally_map_init_alloc(0, None, m), WALLY_OK)

        for args in [(None, key1, key1_len, val,  val_len), # Null map
                     (m,    None, key1_len, val,  val_len), # Null key
                     (m,    key1, 0,        val,  val_len), # 0 length key
                     (m,    key1, key1_len, None, val_len), # Null value
                     (m,    key1, key1_len, val,  0)]:      # 0 length value
            self.assertEqual(wally_map_add(*args), WALLY_EINVAL)
            self.assertEqual(wally_map_replace(*args), WALLY_EINVAL)

        for args in [(None, 1, val,  val_len), # Null map
                     (m,    1, None, val_len), # Null value
                     (m,    1, val,  0)]:      # 0 length value
            self.assertEqual(wally_map_add_integer(*args), WALLY_EINVAL)
            self.assertEqual(wally_map_replace_integer(*args), WALLY_EINVAL)

        for args in [(None, key1, key1_len), # Null map
                     (m,    None, key1_len), # Null key
                     (m,    key1, 0)]:       # 0 length key
            self.assertEqual(wally_map_find(*args), (WALLY_EINVAL, 0))

        self.assertEqual(wally_map_find_integer(None, 1), (WALLY_EINVAL, 0)) # Null map

        self.assertEqual(wally_map_sort(None, 0), WALLY_EINVAL) # Null map
        self.assertEqual(wally_map_sort(m, 1),    WALLY_EINVAL) # Invalid flags

        self.assertEqual(wally_map_free(None), WALLY_OK) # Null is OK

        # Add and find each key
        cases = [(key1, key1_len, val, val_len,   1, 1),
                 (key2, key2_len, val, val_len,   2, 2),
                 (key3, key3_len, val, val_len,   3, 3),
                 (key2, key2_len, val, val_len,   2, 3), # Duplicate Key/Value
                 (key2, key2_len, val, val_len-1, 2, 3)] # Duplicate Key/New Value
        for case in cases:
            k, l, v, vl, i, n = case
            self.assertEqual(wally_map_add(m, k, l, v, vl), WALLY_OK)
            self.assertEqual(wally_map_find(m, k, l), (WALLY_OK, i))
            self.assertEqual(m.contents.num_items, n)
            # Replace the item with shorter key
            self.assertEqual(wally_map_replace(m, k, l, v, vl - 1), WALLY_OK)
            self.assertEqual(wally_map_get_item_length(m, i - 1), (WALLY_OK, vl - 1))
            # Adding an existing key ignores the new value without error.
            vl = vl if case == cases[-1] else vl - 1
            self.assertEqual(m.contents.items[n-1].value_len, vl)

        # Find an integer key with no integers in the map
        self.assertEqual(wally_map_find_integer(m, 1), (WALLY_OK, 0))

        # Sort
        self.assertEqual(wally_map_sort(m, 0), WALLY_OK)

        # Verify sort order
        for k, l, vl, i in [(key1, key1_len, val_len, 3),
                            (key2, key2_len, val_len, 2),
                            (key3, key3_len, val_len, 1)]:
            self.assertEqual(wally_map_find(m, k, l), (WALLY_OK, i))

        # Add and find two integer keys, then replace them
        for i in [9, 5]:
            self.assertEqual(wally_map_add_integer(m, i, val, i * 2), WALLY_OK)
            self.assertEqual(wally_map_find_integer(m, i), (WALLY_OK, m.contents.num_items))
            self.assertEqual(m.contents.items[m.contents.num_items - 1].value_len, i * 2)
            self.assertEqual(wally_map_replace_integer(m, i, val, val_len), WALLY_OK)
            self.assertEqual(m.contents.items[m.contents.num_items - 1].value_len, val_len)

        # Replacing an item that doesn't exist adds it
        num_items = m.contents.num_items
        self.assertEqual(wally_map_replace_integer(m, 10, val, val_len-1), WALLY_OK)
        self.assertEqual(m.contents.num_items, num_items + 1)

        # Sort again, integer keys sort before byte keys
        self.assertEqual(wally_map_sort(m, 0), WALLY_OK)
        self.assertEqual(wally_map_find_integer(m, 5),  (WALLY_OK, 1))
        self.assertEqual(wally_map_find_integer(m, 9),  (WALLY_OK, 2))
        self.assertEqual(wally_map_find_integer(m, 10), (WALLY_OK, 3))

        # Add an empty value
        self.assertEqual(wally_map_add(m, key4, key4_len, empty, empty_len), WALLY_OK)
        self.assertEqual(wally_map_find(m, key4, key4_len), (WALLY_OK, m.contents.num_items))

        # Getter
        self.assertEqual(wally_map_get_item_length(None, 0), (WALLY_EINVAL, 0)) # Null map
        self.assertEqual(wally_map_get_item_length(m, 7), (WALLY_EINVAL, 0)) # Bad index
        self.assertEqual(wally_map_get_item_length(m, 6), (WALLY_OK, 0)) # Zero length is OK

        for args in [(None, 0, out,   out_len),  # Null map
                     (m,    7, out,   out_len),  # Bad index
                     (m,    0, None,  out_len),  # Null output
                     (m,    0, out,   0)]:       # Empty output
            self.assertEqual(wally_map_get_item(*args), (WALLY_EINVAL, 0))

        self.assertEqual(wally_map_get_item(m, 0, out, out_len), (WALLY_OK, 64))
        self.assertEqual(out[:64], val)

        # Assign
        new_key, new_key_len = make_cbuffer('ffffffffff')
        clone = pointer(wally_map())
        self.assertEqual(wally_map_init_alloc(0, None, clone), WALLY_OK)
        self.assertEqual(wally_map_assign(None, m), WALLY_EINVAL)     # No dest map
        self.assertEqual(wally_map_assign(clone, None), WALLY_EINVAL) # No src map
        self.assertEqual(wally_map_assign(clone, clone), WALLY_OK)    # Assign to self: no-op
        self.assertEqual(wally_map_add(clone, new_key, new_key_len, v, vl), WALLY_OK)
        # Assign over the map; the exiting entry is deleted
        self.assertEqual(wally_map_assign(clone, m), WALLY_OK)
        self.assertEqual(wally_map_find(clone, new_key, new_key_len), (WALLY_OK, 0))

        # Re-create clone to test combining
        self.assertEqual(wally_map_free(clone), WALLY_OK);
        self.assertEqual(wally_map_init_alloc(0, None, clone), WALLY_OK)
        self.assertEqual(wally_map_add(clone, new_key, new_key_len, v, vl), WALLY_OK)

        # Combine
        self.assertEqual(wally_map_combine(None, m), WALLY_EINVAL) # No dest map
        self.assertEqual(wally_map_combine(m, None), WALLY_OK)     # No src: no-op
        num_items = m.contents.num_items
        self.assertEqual(wally_map_combine(m, m), WALLY_OK)        # Combine w/self: no-op
        self.assertEqual(m.contents.num_items, num_items)
        self.assertEqual(wally_map_combine(m, clone), WALLY_OK)
        self.assertEqual(m.contents.num_items, num_items + 1)      # Added the clone item

        # Remove
        for args in [(None, key1, key1_len), # Null map
                     (m,    None, key1_len), # Null key
                     (m,    key1, 0)]:       # 0 length key
            self.assertEqual(wally_map_remove(*args), WALLY_EINVAL)
        self.assertEqual(wally_map_remove_integer(None, 1), WALLY_EINVAL)

        # Returns OK if key is not present
        self.assertEqual(wally_map_remove(m, key1, key1_len - 1), WALLY_OK)
        self.assertEqual(wally_map_remove_integer(m, 50), WALLY_OK)

        num_items = m.contents.num_items
        self.assertEqual(wally_map_remove(m, key2, key2_len), WALLY_OK)
        self.assertEqual(m.contents.num_items, num_items - 1) # Removed key2
        self.assertEqual(wally_map_remove_integer(m, 5), WALLY_OK)
        self.assertEqual(m.contents.num_items, num_items - 2) # Removed 5

        self.assertEqual(wally_map_free(m), WALLY_OK)

    def test_keypath_map(self):
        """Test keypath map functions"""
        #
        # BIP32
        #
        m = pointer(wally_map())
        self.assertEqual(wally_map_keypath_bip32_init_alloc(0, None), WALLY_EINVAL)
        self.assertEqual(wally_map_keypath_bip32_init_alloc(0, m), WALLY_OK)

        master = get_test_master_key(vec_1)
        fingerprint, path = (c_ubyte * 4)(), (c_uint * 5)()
        path = (c_uint * 5)()
        path[0], path[1], path[2], path[3], path[4] = (0x80000044, 0x80000000, 0x80000000, 0, 1)

        derived = pointer(ext_key())
        ret = bip32_key_from_parent_path(byref(master), path, len(path), 0, derived)
        self.assertEqual(ret, WALLY_OK)

        ret = bip32_key_get_fingerprint(derived, fingerprint, len(fingerprint))
        self.assertEqual(ret, WALLY_OK)

        path_bytes = b''.join([i.to_bytes(4, byteorder='little') for i in path])
        kp_path = bytes(fingerprint) + path_bytes

        bip32, bip32_len = make_cbuffer('00' * BIP32_LEN)
        ret = bip32_key_serialize(derived, FLAG_KEY_PUBLIC, bip32, bip32_len)
        self.assertEqual(ret, WALLY_OK)

        # Check validation works
        ret = wally_keypath_bip32_verify(bip32, bip32_len, kp_path, len(kp_path))
        self.assertEqual(ret, WALLY_OK)

        # Invalid keypaths
        cases = [
            (None,  bip32_len, kp_path, len(kp_path)),   # NULL key
            (bip32, 0,         kp_path, len(kp_path)),   # Zero length key
            (bip32, 33,        kp_path, len(kp_path)),   # Pubkey key
            (bip32, 65,        kp_path, len(kp_path)),   # Uncompressed pubkey key
            (bip32, bip32_len, None,    len(kp_path)),   # NULL value
            (bip32, bip32_len, kp_path, 0),              # Zero length value
            (bip32, bip32_len, kp_path, len(kp_path)-1), # Value length not % 4
            (bip32, bip32_len, kp_path, len(kp_path)-4), # Value depth mismatch
        ]
        for args in cases:
            self.assertEqual(wally_keypath_bip32_verify(*args), WALLY_EINVAL)
            # TODO: Enable with map function validation
            #self.assertEqual(wally_map_add(m, *args), WALLY_EINVAL)

        self.assertEqual(wally_map_free(m), WALLY_OK)

        #
        # Public key
        #
        m = pointer(wally_map())
        self.assertEqual(wally_map_keypath_public_key_init_alloc(0, None), WALLY_EINVAL)
        self.assertEqual(wally_map_keypath_public_key_init_alloc(0, m), WALLY_OK)

        pub_key, pub_key_len = derived.contents.pub_key, 33
        pub_key_u, pub_key_u_len = make_cbuffer('00' * 65)
        ret = wally_ec_public_key_decompress(pub_key, pub_key_len, pub_key_u, pub_key_u_len)
        self.assertEqual(ret, WALLY_OK)

        # Check validation works
        ret = wally_keypath_public_key_verify(pub_key, pub_key_len, kp_path, len(kp_path))
        self.assertEqual(ret, WALLY_OK)
        ret = wally_keypath_public_key_verify(pub_key_u, pub_key_u_len, kp_path, len(kp_path))
        self.assertEqual(ret, WALLY_OK)

        cases = [
            (None,  pub_key_len,   kp_path, len(kp_path)),   # NULL key
            (pub_key, 0,           kp_path, len(kp_path)),   # Zero length key
            (pub_key, BIP32_LEN,   kp_path, len(kp_path)),   # Extended pubkey key len
            (pub_key, pub_key_len, None,    len(kp_path)),   # NULL value
            (pub_key, pub_key_len, kp_path, 0),              # Zero length value
            (pub_key, pub_key_len, kp_path, len(kp_path)-1), # Value length not % 4
        ]
        for args in cases:
            self.assertEqual(wally_keypath_public_key_verify(*args), WALLY_EINVAL)
            # TODO: Enable with map function validation
            #self.assertEqual(wally_map_add(m, *args), WALLY_EINVAL)

        self.assertEqual(wally_map_free(m), WALLY_OK)

    def test_preimage_map(self):
        """Test preimage map functions"""
        m = pointer(wally_map())
        self.assertEqual(wally_map_preimage_init_alloc(0, None), WALLY_EINVAL)
        self.assertEqual(wally_map_preimage_init_alloc(0, m), WALLY_OK)

        data, data_len = make_cbuffer('00' * 50) # Arbitrary data

        for fn in [wally_map_preimage_ripemd160_add, wally_map_preimage_sha256_add,
                   wally_map_preimage_hash160_add, wally_map_preimage_sha256d_add]:
            for args in [(None, data, data_len), # NULL map
                         (m, None, data_len),    # NULL data
                         (m, data, 0)]:          # Zero length data
                self.assertEqual(fn(*args), WALLY_EINVAL)


if __name__ == '__main__':
    unittest.main()
