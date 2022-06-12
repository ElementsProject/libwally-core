import json
import unittest
from util import *

FLAG_GRIND_R = 0x4
MOD_NONE = 0

with open(root_dir + 'src/data/psbt.json', 'r') as f:
    JSON = json.load(f)


class PSBTTests(unittest.TestCase):

    def parse_base64(self, src_base64, expected=WALLY_OK):
        psbt = pointer(wally_psbt())
        ret = wally_psbt_from_base64(src_base64, psbt)
        self.assertEqual(ret, expected, "{0}".format(src_base64))
        return psbt

    def to_base64(self, psbt, mod_flags=None):
        """Dump a PSBT to base64, optionally overriding tx modifiable flags"""
        if mod_flags is not None:
            version = wally_psbt_get_version(psbt)[1]
            if version != 2:
                mod_flags = None # Ignore for v0 PSBTs
            else:
                ret, old_flags = wally_psbt_get_tx_modifiable_flags(psbt)
                self.assertEqual(ret, WALLY_OK)
                ret = wally_psbt_set_tx_modifiable_flags(psbt, mod_flags)
                self.assertEqual(ret, WALLY_OK)
        ret, base64 = wally_psbt_to_base64(psbt, 0)
        self.assertEqual(ret, WALLY_OK)
        if mod_flags is not None:
            ret = wally_psbt_set_tx_modifiable_flags(psbt, old_flags)
            self.assertEqual(ret, WALLY_OK)
        return base64

    def test_invalid(self):
        """Test deserializing invalid PSBTs"""
        for case in JSON['invalid']:
            wally_psbt_free(self.parse_base64(case['psbt'], WALLY_EINVAL))

    def test_valid(self):
        """Test deserializing and roundtripping valid PSBTs"""
        buf, buf_len = make_cbuffer('00' * 4096)
        _, is_elements_build = wally_is_elements_build()
        clone = pointer(wally_psbt())

        for case in JSON['valid']:
            if case.get('is_pset', False) and not is_elements_build:
                continue # No Elements support, skip this test case

            psbt = self.parse_base64(case['psbt'])
            self.assertEqual(self.to_base64(psbt), case['psbt'])

            ret = wally_psbt_clone_alloc(psbt, 0, clone)
            self.assertEqual(self.to_base64(clone), case['psbt'])
            wally_psbt_free(clone)

            ret, length = wally_psbt_get_length(psbt, 0)
            self.assertEqual(ret, WALLY_OK)


            ret, written = wally_psbt_to_bytes(psbt, 0, buf, buf_len)
            self.assertEqual((ret, written), (WALLY_OK, length))
            wally_psbt_free(psbt)

    def test_creator_role(self):
        """Test the PSBT creator role"""
        psbt = pointer(wally_psbt())

        for case in JSON['creator']:
            self.assertEqual(WALLY_OK, wally_psbt_init_alloc(case['version'], 2, 3, 0, 0, psbt))

            tx = pointer(wally_tx())
            self.assertEqual(WALLY_OK, wally_tx_init_alloc(2, 0, 2, 2, tx))

            for i, txin in enumerate(case['inputs']):
                tx_in = pointer(wally_tx_input())
                txid, txid_len = make_cbuffer(txin['txid'])
                ret = wally_tx_input_init_alloc(txid[::-1], txid_len, txin['vout'], 0xffffffff, None, 0, None, tx_in)
                self.assertEqual(WALLY_OK, ret)

                if (case['version'] == 0):
                    self.assertEqual(WALLY_OK, wally_tx_add_input(tx, tx_in))
                else:
                    self.assertEqual(WALLY_OK, wally_psbt_add_input_at(psbt, i, 0, tx_in))

            for i, txout in enumerate(case['outputs']):
                address, satoshi = txout['address'], txout['satoshi']
                spk, spk_len = make_cbuffer('00' * (32 + 2))
                ret, written = wally_addr_segwit_to_bytes(address, 'bcrt', 0, spk, spk_len)
                self.assertEqual(WALLY_OK, ret)
                output = pointer(wally_tx_output())
                self.assertEqual(WALLY_OK, wally_tx_output_init_alloc(satoshi, spk, written, output))
                if (case['version'] == 0):
                    self.assertEqual(WALLY_OK, wally_tx_add_output(tx, output))
                else:
                    self.assertEqual(WALLY_OK, wally_psbt_add_output_at(psbt, i, 0, output))

            if (case['version'] == 0):
                self.assertEqual(WALLY_OK, wally_psbt_set_global_tx(psbt, tx))

            self.assertEqual(self.to_base64(psbt, MOD_NONE), case['result'])
            wally_psbt_free(psbt)

    def test_combiner_role(self):
        """Test the PSBT combiner role"""
        for case in JSON['combiner']:
            psbt = self.parse_base64(case['psbts'][0])
            for src_b64 in case['psbts'][1:]:
                src = self.parse_base64(src_b64)
                self.assertEqual(WALLY_OK, wally_psbt_combine(psbt, src))
                wally_psbt_free(src)
            self.assertEqual(self.to_base64(psbt), case['result'])
            wally_psbt_free(psbt)

    def do_sign(self, b64, wifs, expected=WALLY_OK):
        priv_key, priv_key_len = make_cbuffer('00'*32)
        psbt = self.parse_base64(b64)
        for wif in wifs:
            self.assertEqual(WALLY_OK, wally_wif_to_bytes(wif, 0xEF, 0, priv_key, priv_key_len))
            self.assertEqual(expected, wally_psbt_sign(psbt, priv_key, priv_key_len, FLAG_GRIND_R))
        return psbt

    def test_signer_role(self):
        """Test the PSBT signer role"""
        for case in JSON['signer']:
            psbt = self.do_sign(case['psbt'], case['privkeys'])

            # Check that we can roundtrip the signed PSBT (some bugs only appear here)
            b64_out = self.to_base64(psbt)
            wally_psbt_free(psbt)
            psbt = self.parse_base64(b64_out)
            self.assertEqual(case['result'], b64_out)
            wally_psbt_free(psbt)

        for case in JSON['invalid_signer']:
            psbt = self.do_sign(case['psbt'], case['privkeys'], WALLY_EINVAL)
            wally_psbt_free(psbt)

    def test_finalizer_role(self):
        """Test the PSBT finalizer role"""
        for case in JSON['finalizer']:
            psbt = self.parse_base64(case['psbt'])
            self.assertEqual(WALLY_OK, wally_psbt_finalize(psbt))
            ret, is_finalized = wally_psbt_is_finalized(psbt)
            self.assertEqual((ret, is_finalized), (WALLY_OK, 1))
            self.assertEqual(self.to_base64(psbt), case['result'])
            wally_psbt_free(psbt)

    def test_extractor_role(self):
        """Test the PSBT extractor role"""
        for case in JSON['extractor']:
            psbt = self.parse_base64(case['psbt'])
            tx = pointer(wally_tx())
            self.assertEqual(WALLY_OK, wally_psbt_extract(psbt, tx))
            ret, tx_hex = wally_tx_to_hex(tx, 1)
            self.assertEqual((ret, tx_hex), (WALLY_OK, case['result']))
            wally_tx_free(tx)
            wally_psbt_free(psbt)

    def test_map(self):
        """Test PSBT map helper functions"""
        m = pointer(wally_map())
        # Test keys. Once sorted we expect order k3, k2, k1
        key1, key1_len = make_cbuffer('505050')
        key2, key2_len = make_cbuffer('40404040')
        key3, key3_len = make_cbuffer('404040')
        val, val_len = make_cbuffer('ffffffff')

        # Check invalid args
        self.assertEqual(wally_map_init_alloc(0, None), WALLY_EINVAL)
        self.assertEqual(wally_map_init_alloc(0, m), WALLY_OK)

        for args in [(None, key1, key1_len, val,  val_len), # Null map
                     (m,    None, key1_len, val,  val_len), # Null key
                     (m,    key1, 0,        val,  val_len), # 0 length key
                     (m,    key1, key1_len, None, val_len), # Null value
                     (m,    key1, key1_len, val,  0)]:      # 0 length value
            self.assertEqual(wally_map_add(*args), WALLY_EINVAL)
            # TODO: wally_map_add_keypath_item

        for args in [(None, key1, key1_len), # Null map
                     (m,    None, key1_len), # Null key
                     (m,    key1, 0)]:       # 0 length key
            self.assertEqual(wally_map_find(*args), (WALLY_EINVAL, 0))

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
            # Adding an existing key ignores the new value without error.
            vl = vl + 1 if case == cases[-1] else vl
            self.assertEqual(m.contents.items[n-1].value_len, vl)

        # Sort
        self.assertEqual(wally_map_sort(m, 0), WALLY_OK)

        # Verify sort order
        for k, l, vl, i in [(key1, key1_len, val_len, 3),
                            (key2, key2_len, val_len, 2),
                            (key3, key3_len, val_len, 1)]:
            self.assertEqual(wally_map_find(m, k, l), (WALLY_OK, i))

        self.assertEqual(wally_map_free(m), WALLY_OK)

    def test_v20dot1_changes(self):
        """See https://github.com/ElementsProject/libwally-core/issues/213
           Verify that core v20.1 changes to address the segwit fee attack now work"""
        b64 = 'cHNidP8BAJoCAAAAAvezqpNxOIDkwNFhfZVLYvuhQxqmqNPJwlyXbhc8cuLPAQAAAAD9////krlOMdd9VVzPWn5+oadTb4C3NnUFWA3tF6cb1RiI4JAAAAAAAP3///8CESYAAAAAAAAWABQn/PFABd2EW5RsCUvJitAYNshf9BAnAAAAAAAAFgAUFpodxCngMIyYnbJ1mhpDwQykN4cAAAAAAAEAiQIAAAABfRJscM0GWu793LYoAX15Mnj+dVr0G7yvRMBeWSmvPpQAAAAAFxYAFESkW2FnrJlkwmQZjTXL1IVM95lW/f///wK76QAAAAAAABYAFB33sq8WtoOlpvUpCvoWbxJJl5rhECcAAAAAAAAXqRTFhAlcZBMRkG4iAustDT6iSw6wkIcAAAAAAQEgECcAAAAAAAAXqRTFhAlcZBMRkG4iAustDT6iSw6wkIcBBBYAFIsieXd6AAeP8TXHKZ329Z0nuSeZIgYD/ajyzV90ghQ+0zIO2mVSd3fGYhvwYjakGCY4WNYxoeYEiyJ5dwABAHICAAAAAfezqpNxOIDkwNFhfZVLYvuhQxqmqNPJwlyXbhc8cuLPAAAAAAD9////AhAnAAAAAAAAF6kUXJfUn/nNbND+a+QhqHnyCSy9oPmHHcIAAAAAAAAWABSUD3a8pIYaaLvKdZxoEPFfo8vlDwAAAAABASAQJwAAAAAAABepFFyX1J/5zWzQ/mvkIah58gksvaD5hwEEFgAUyRIBhZwlI4RLT6NDHluovlrN3iAiBgIs+YA2N8B5O6nF4SgVEG765xfHZFKrLiKbjZuo8/9vPATJEgGFACICAq8h+ABETC5Tczuts3xhCtXAzIEUHM5iMugvwFMrtCc4EBK06cYAAACAAQAAgMMAAIAAAA=='
        psbt = self.parse_base64(b64)
        buf, buf_len = make_cbuffer('00'*32)
        for priv in ['cTatuMdjH4YA4F1pAm11QdbCt88T8t2TTMoAvVGzAxWAWmQZtkBZ',
                     'cR5yyo2g1SzzwCw2QAREzF7XhYuXZS9SzTTf8A9qerri9EXZcRYS']:
            self.assertEqual(wally_wif_to_bytes(priv, 0xEF, 0, buf, buf_len), WALLY_OK)
            self.assertEqual(wally_psbt_sign(psbt, buf, buf_len, FLAG_GRIND_R), WALLY_OK)
        self.assertEqual(wally_psbt_finalize(psbt), WALLY_OK)

        expected = 'cHNidP8BAJoCAAAAAvezqpNxOIDkwNFhfZVLYvuhQxqmqNPJwlyXbhc8cuLPAQAAAAD9////krlOMdd9VVzPWn5+oadTb4C3NnUFWA3tF6cb1RiI4JAAAAAAAP3///8CESYAAAAAAAAWABQn/PFABd2EW5RsCUvJitAYNshf9BAnAAAAAAAAFgAUFpodxCngMIyYnbJ1mhpDwQykN4cAAAAAAAEAiQIAAAABfRJscM0GWu793LYoAX15Mnj+dVr0G7yvRMBeWSmvPpQAAAAAFxYAFESkW2FnrJlkwmQZjTXL1IVM95lW/f///wK76QAAAAAAABYAFB33sq8WtoOlpvUpCvoWbxJJl5rhECcAAAAAAAAXqRTFhAlcZBMRkG4iAustDT6iSw6wkIcAAAAAAQEgECcAAAAAAAAXqRTFhAlcZBMRkG4iAustDT6iSw6wkIcBBxcWABSLInl3egAHj/E1xymd9vWdJ7knmQEIawJHMEQCIAkPXe9sdpRjSDTjJ0gIrpwGGIWJby9xSd1rS9hPe1f0AiAJgqR7PL3G/MXyUu4KZdS1Z2O14fjxstF43k634u+4GAEhA/2o8s1fdIIUPtMyDtplUnd3xmIb8GI2pBgmOFjWMaHmAAEAcgIAAAAB97Oqk3E4gOTA0WF9lUti+6FDGqao08nCXJduFzxy4s8AAAAAAP3///8CECcAAAAAAAAXqRRcl9Sf+c1s0P5r5CGoefIJLL2g+YcdwgAAAAAAABYAFJQPdrykhhpou8p1nGgQ8V+jy+UPAAAAAAEBIBAnAAAAAAAAF6kUXJfUn/nNbND+a+QhqHnyCSy9oPmHAQcXFgAUyRIBhZwlI4RLT6NDHluovlrN3iABCGsCRzBEAiAOzRsNZ+2Et+VGCY/nXWO7WxGI3u39kpi025cUaJXQJgIgL6KtMqPfAwXGktQFWr9SNnOrHF2xjvKQI2VdeuQbxt0BIQIs+YA2N8B5O6nF4SgVEG765xfHZFKrLiKbjZuo8/9vPAAiAgKvIfgAREwuU3M7rbN8YQrVwMyBFBzOYjLoL8BTK7QnOBAStOnGAAAAgAEAAIDDAACAAAA='
        self.assertEqual(self.to_base64(psbt), expected)

    def test_psbt(self):
        """Test creating and modifying various PSBT fields"""
        tx = pointer(wally_tx())
        self.assertEqual(WALLY_OK, wally_tx_init_alloc(2, 0, 2, 2, tx))

        psbt = pointer(wally_psbt())
        for ver, result in [
            (0, 'cHNidP8A'),
            (1, None),
            (2, 'cHNidP8B+wQCAAAAAQIEAgAAAAEEAQABBQEAAA=='),
            (3, None) ]:
            ret = wally_psbt_init_alloc(ver, 0, 0, 0, 0, psbt)
            self.assertEqual(ret, WALLY_OK if result else WALLY_EINVAL)
            if result:
                self.assertEqual(self.to_base64(psbt, MOD_NONE), result)

                # Global tx can only be set on a version 0 PSBT
                ret = wally_psbt_set_global_tx(psbt, tx)
                self.assertEqual(ret, WALLY_OK if ver == 0 else WALLY_EINVAL)

        # Create a v2 PSBT
        wally_psbt_init_alloc(2, 0, 0, 0, 0, psbt)

        self.assertEqual(wally_psbt_set_tx_version(psbt, 123), WALLY_OK)
        self.assertEqual(self.to_base64(psbt, MOD_NONE), 'cHNidP8B+wQCAAAAAQIEewAAAAEEAQABBQEAAA==')

        self.assertEqual(wally_psbt_set_fallback_locktime(psbt, 456), WALLY_OK)
        self.assertEqual(self.to_base64(psbt, MOD_NONE), 'cHNidP8B+wQCAAAAAQIEewAAAAEDBMgBAAABBAEAAQUBAAA=')

        self.assertEqual(wally_psbt_clear_fallback_locktime(psbt), WALLY_OK)
        self.assertEqual(self.to_base64(psbt, MOD_NONE), 'cHNidP8B+wQCAAAAAQIEewAAAAEEAQABBQEAAA==')

        self.assertEqual(wally_psbt_set_tx_modifiable_flags(psbt, 3), WALLY_OK)
        self.assertEqual(self.to_base64(psbt), 'cHNidP8B+wQCAAAAAQIEewAAAAEEAQABBQEAAQYBAwA=')

        # Create an input
        tx_input = pointer(wally_tx_input())

        txhash, txhash_len = make_cbuffer('e7f25add4560021c77c4944f92739025fddbf99816d79c06d219268ca9f4b7e7')
        ret = wally_tx_input_init_alloc(txhash, txhash_len, 5, 6, b'\x59', 1, None, tx_input)
        self.assertEqual(WALLY_OK, ret)
        ret = wally_psbt_add_input_at(psbt, 0, 0, tx_input)
        self.assertEqual(WALLY_OK, ret)
        ret, base64 = wally_psbt_to_base64(psbt, 0)
        self.assertEqual(WALLY_OK, ret)
        self.assertEqual('cHNidP8B+wQCAAAAAQIEewAAAAEEAQEBBQEAAQYBAwABDiDn8lrdRWACHHfElE+Sc5Al/dv5mBbXnAbSGSaMqfS35wEPBAUAAAABEAQGAAAAAA==', base64)

        ret = wally_psbt_input_set_required_lockheight(psbt.contents.inputs[0], 499999999)
        self.assertEqual(WALLY_OK, ret)
        ret, base64 = wally_psbt_to_base64(psbt, 0)
        self.assertEqual(WALLY_OK, ret)
        self.assertEqual('cHNidP8B+wQCAAAAAQIEewAAAAEEAQEBBQEAAQYBAwABDiDn8lrdRWACHHfElE+Sc5Al/dv5mBbXnAbSGSaMqfS35wEPBAUAAAABEAQGAAAAARIE/2TNHQA=', base64)

        tx_output = pointer(wally_tx_output())

        wally_tx_output_init_alloc(1234, b'\x59\x59', 2, tx_output)
        self.assertEqual(WALLY_OK, ret)
        ret = wally_psbt_add_output_at(psbt, 0, 0, tx_output)
        self.assertEqual(WALLY_OK, ret)

        ret, base64 = wally_psbt_to_base64(psbt, 0)
        self.assertEqual(WALLY_OK, ret)
        self.assertEqual('cHNidP8B+wQCAAAAAQIEewAAAAEEAQEBBQEBAQYBAwABDiDn8lrdRWACHHfElE+Sc5Al/dv5mBbXnAbSGSaMqfS35wEPBAUAAAABEAQGAAAAARIE/2TNHQABAwjSBAAAAAAAAAEEAllZAA==', base64)

    def test_invalid_args(self):
        """Test invalid arguments to various PSBT functions"""
        psbt = pointer(wally_psbt())

        # psbt_from_base64
        src_base64 = JSON['valid'][0]['psbt']
        for args in [(None,       psbt),  # NULL base64
                     ('',         psbt),  # Invalid flags
                     (src_base64, None)]: # NULL dest
            self.assertEqual(WALLY_EINVAL, wally_psbt_from_base64(*args))

        self.assertEqual(WALLY_OK, wally_psbt_from_base64(JSON['valid'][0]['psbt'], psbt))

        # psbt_clone_alloc
        clone = pointer(wally_psbt())
        for args in [(None, 0x0, clone), # NULL src
                     (psbt, 0x1, clone), # Invalid flags
                     (psbt, 0x0, None)]: # NULL dest
            self.assertEqual(WALLY_EINVAL, wally_psbt_clone_alloc(*args))

if __name__ == '__main__':
    unittest.main()
