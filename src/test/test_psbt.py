import json
import unittest
from ctypes import string_at
from util import *

FLAG_GRIND_R = 0x4
MOD_NONE = 0
INIT_PSET = 1
WALLY_PSBT_EXTRACT_NON_FINAL = 0x1
WALLY_SILENT_PAYMENT_KEYS_LEN = 66

with open(root_dir + 'src/data/psbt.json', 'r') as f:
    JSON = json.load(f)


class PSBTTests(unittest.TestCase):

    def parse_base64(self, src_base64, expected=WALLY_OK, flags=0):
        psbt = pointer(wally_psbt())
        ret = wally_psbt_from_base64(src_base64, flags, psbt)
        self.assertEqual(ret, expected, "{0}".format(src_base64))
        return psbt

    def to_base64(self, psbt, mod_flags=None, flags=0):
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
        ret, base64 = wally_psbt_to_base64(psbt, flags)
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
            is_pset = case.get('is_pset', False)
            if is_pset and not is_elements_build:
                continue # No Elements support, skip this test case

            # Cases that test workarounds for elements serialization bugs
            # don't directly round trip, as wally doesn't reproduce those bugs
            can_round_trip = case.get('can_round_trip', True)

            psbt = self.parse_base64(case['psbt'])
            self.assertEqual(wally_psbt_is_elements(psbt)[1], 1 if is_pset else 0)

            serialized = self.to_base64(psbt)
            expected = case['psbt']
            if not can_round_trip:
                # Make sure the good serialization can round-trip
                good_psbt = self.parse_base64(serialized)
                expected = self.to_base64(good_psbt)
                wally_psbt_free(good_psbt)
            self.assertEqual(serialized, expected)

            ret = wally_psbt_clone_alloc(psbt, 0, clone)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(self.to_base64(clone), serialized)
            wally_psbt_free(clone)

            ret, length = wally_psbt_get_length(psbt, 0)
            self.assertEqual(ret, WALLY_OK)

            ret, written = wally_psbt_to_bytes(psbt, 0, buf, buf_len)
            self.assertEqual((ret, written), (WALLY_OK, length))

            if not is_pset:
                version = wally_psbt_get_version(psbt)[1]
                tx = pointer(wally_tx())
                NON_FINAL = 0x1 # Don't require a finalized tx to extract
                USE_WITNESS = 0x1
                if wally_psbt_extract(psbt, NON_FINAL, tx) == WALLY_OK:
                    # Upgrade/Downgrade and make sure the same tx is extracted
                    pre_hex = wally_tx_to_hex(tx, USE_WITNESS)[1]
                    tx_version = tx.contents.version
                    new_version = 2 if version == 0 else 0
                    ret = wally_psbt_set_version(psbt, 0, new_version)
                    self.assertEqual(ret, WALLY_OK)
                    ret = wally_psbt_extract(psbt, NON_FINAL, tx)
                    self.assertEqual(ret, WALLY_OK)
                    if new_version == 2:
                        # Restore the tx version in case a v0/v1 tx was upgraded
                        tx.contents.version = tx_version
                    post_hex = wally_tx_to_hex(tx, USE_WITNESS)[1]
                    self.assertEqual(pre_hex, post_hex)

                    if new_version == 0:
                        # Upgrading to v2 fails if no global tx is present
                        wally_tx_free(psbt.contents.tx)
                        psbt.contents.tx = None
                        self.assertEqual(wally_psbt_set_version(psbt, 0, 2),
                                         WALLY_EINVAL)

            wally_psbt_free(psbt)

    def test_global_tx_malloc_fail(self):
        """Test allocation failures when setting a v0 PSBTs global tx"""
        # Failing any allocation, including the input and output
        # arrays, must fail cleanly with WALLY_ENOMEM
        tx_hex = '0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300'
        tx = pointer(wally_tx())
        self.assertEqual(wally_tx_from_hex(tx_hex, 1, tx), WALLY_OK)

        results = set()
        max_mallocs = 8

        @malloc_fail(range(max_mallocs))
        def check_set_global_tx():
            psbt = pointer(wally_psbt())
            ret = wally_psbt_init_alloc(0, 0, 0, 0, 0, psbt)
            if ret == WALLY_OK:
                ret = wally_psbt_set_global_tx(psbt, tx)
                wally_psbt_free(psbt)
            self.assertIn(ret, [WALLY_OK, WALLY_ENOMEM])
            results.add(ret)

        num_mallocs = check_set_global_tx()
        self.assertEqual(num_mallocs, max_mallocs)
        self.assertEqual(results, {WALLY_OK, WALLY_ENOMEM})
        wally_tx_free(tx)

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
                    self.assertEqual(WALLY_OK, wally_psbt_add_tx_input_at(psbt, i, 0, tx_in))

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
                    self.assertEqual(WALLY_OK, wally_psbt_add_tx_output_at(psbt, i, 0, output))

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

        # Invalid cases
        psbt = self.parse_base64(JSON['combiner'][0]['psbts'][0])
        src = self.parse_base64(JSON['combiner'][0]['psbts'][1])
        self.assertEqual(WALLY_EINVAL, wally_psbt_combine(None, src))        # Null dest
        self.assertEqual(WALLY_EINVAL, wally_psbt_combine(psbt, None))       # Null src
        self.assertEqual(WALLY_EINVAL, wally_psbt_combine_ex(None, 0, src))  # Null dest
        self.assertEqual(WALLY_EINVAL, wally_psbt_combine_ex(psbt, 4, src))  # Unknown flags
        self.assertEqual(WALLY_EINVAL, wally_psbt_combine_ex(psbt, 0, None)) # Null src
        self.assertEqual(WALLY_EINVAL, wally_psbt_combine_ex(psbt, 1, src))  # Non-sig-only src

    def roundtrip(self, psbt, expected=None):
        b64_out = self.to_base64(psbt)
        if expected:
            self.maxDiff = None
            self.assertEqual(b64_out, expected)
        wally_psbt_free(psbt)
        psbt = self.parse_base64(b64_out)
        self.assertEqual(b64_out, self.to_base64(psbt))
        wally_psbt_free(psbt)
        return b64_out

    def check_signature_only_psbt(self, unsigned_b64, signed_b64):
        FLAG_SIGS_ONLY = 0x2 # WALLY_PSBT_SERIALIZE_SIGS_ONLY
        FLAG_LOOSE = 0x2 # WALLY_PSBT_PARSE_FLAG_LOOSE
        FLAG_COMBINE_SIGS = 0x1 # WALLY_PSBT_COMBINE_SIGS

        # Convert the signed PSBT into a signature-only PSBT
        signed = self.parse_base64(signed_b64)
        sigs_only_b64 = self.to_base64(signed, flags=FLAG_SIGS_ONLY)
        sigs_only = self.parse_base64(sigs_only_b64, flags=FLAG_LOOSE)
        # Combine the sigs-only PSBT with the unsigned PSBT
        unsigned = self.parse_base64(unsigned_b64)
        ret = wally_psbt_combine_ex(unsigned, FLAG_COMBINE_SIGS, sigs_only)
        # Ensure the resulting combined PSBT matches the signed psbt
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(self.to_base64(unsigned), signed_b64)

    def do_sign(self, case):
        expected = case.get('result', None)
        expected_ret = WALLY_OK if expected else WALLY_EINVAL
        priv_key, priv_key_len = make_cbuffer('00'*32)
        # Sign with all private keys available, checking all allocations
        psbt, signed = None, None
        for wif in case['privkeys']:
            ret = wally_wif_to_bytes(wif, 0xEF, 0, priv_key, priv_key_len)
            self.assertEqual(ret, WALLY_OK)
            def do_sign():
                with no_malloc_failures():
                    nonlocal psbt
                    psbt = signed if signed else self.parse_base64(case['psbt'])
                    wally_psbt_signing_cache_enable(psbt, 0) # Enable signing cache
                return wally_psbt_sign(psbt, priv_key, priv_key_len, FLAG_GRIND_R)
            # OK is allowed because failure to encache an item is not fatal
            ret = malloc_fail_loop(do_sign, allowed_rets=[WALLY_ENOMEM, WALLY_OK])
            self.assertEqual(expected_ret, ret)
            signed = psbt
        # Check that we can roundtrip the signed PSBT (some bugs only appear here)
        b64_out = self.roundtrip(psbt, expected)
        self.check_signature_only_psbt(case['psbt'], b64_out)

        if expected and case.get('master_xpriv', None):
            # Test signing with the master extended private key.
            # Note we cannot check for equality with the explicit private keys
            # in all cases, since the PSBTs contain multiple keys from the same
            # master, and some test cases only give a subset as explicit private keys.
            key_out = POINTER(ext_key)()
            ret = bip32_key_from_base58_alloc(case['master_xpriv'], byref(key_out))
            self.assertEqual(ret, WALLY_OK)
            psbt = self.parse_base64(case['psbt'])
            wally_psbt_signing_cache_enable(psbt, 0) # Enable signing cache
            ret = wally_psbt_sign_bip32(psbt, key_out, 0x4)
            # If all of the explicit private keys resulting from the master xpriv
            # are present, we can verify the fully signed result matches exactly
            can_match = case.get('all_privkeys_present', False)
            b64_out = self.roundtrip(psbt, expected if can_match else None)
            if not can_match:
                # Check that the result changed at least, i.e. some inputs were signed
                self.assertNotEqual(b64_out, case['psbt'])
            self.check_signature_only_psbt(case['psbt'], b64_out)
            bip32_key_free(key_out)

    def test_signer_role(self):
        """Test the PSBT signer role"""
        _, is_elements_build = wally_is_elements_build()

        for case in JSON['signer']:
            if is_elements_build or not case.get('is_pset', False):
                self.do_sign(case)

        for case in JSON['invalid_signer']:
            if is_elements_build or not case.get('is_pset', False):
                self.do_sign(case)

    def test_finalizer_role(self):
        """Test the PSBT finalizer role"""
        _, is_elements_build = wally_is_elements_build()
        SERIALIZE_FLAG_REDUNDANT = 0x1
        for case in JSON['finalizer']:
            is_pset = case.get('is_pset', False)
            expected_ret = WALLY_EINVAL if is_pset and not is_elements_build else WALLY_OK
            psbt = self.parse_base64(case['psbt'], expected_ret)
            flags = case['flags']
            ret = wally_psbt_finalize(psbt, flags)
            self.assertEqual(ret, expected_ret);
            if expected_ret == WALLY_OK:
                ret, is_finalized = wally_psbt_is_finalized(psbt)
                self.assertEqual((ret, is_finalized), (WALLY_OK, 1))
                extract_flags = SERIALIZE_FLAG_REDUNDANT if flags == 1 else 0
                self.assertEqual(self.to_base64(psbt, flags=extract_flags), case['result'])
                wally_psbt_free(psbt)

    def test_extractor_role(self):
        """Test the PSBT extractor role"""
        _, is_elements_build = wally_is_elements_build()

        for case in JSON['extractor']:
            if case.get('is_pset', False) and not is_elements_build:
                continue # No Elements support, skip this test case

            psbt = self.parse_base64(case['psbt'])
            tx = pointer(wally_tx())
            self.assertEqual(WALLY_OK, wally_psbt_extract(psbt, 0, tx))
            ret, tx_hex = wally_tx_to_hex(tx, 1)
            self.assertEqual((ret, tx_hex), (WALLY_OK, case['result']))
            wally_tx_free(tx)
            wally_psbt_free(psbt)

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
        self.assertEqual(wally_psbt_finalize(psbt, 0), WALLY_OK)

        expected = 'cHNidP8BAJoCAAAAAvezqpNxOIDkwNFhfZVLYvuhQxqmqNPJwlyXbhc8cuLPAQAAAAD9////krlOMdd9VVzPWn5+oadTb4C3NnUFWA3tF6cb1RiI4JAAAAAAAP3///8CESYAAAAAAAAWABQn/PFABd2EW5RsCUvJitAYNshf9BAnAAAAAAAAFgAUFpodxCngMIyYnbJ1mhpDwQykN4cAAAAAAAEAiQIAAAABfRJscM0GWu793LYoAX15Mnj+dVr0G7yvRMBeWSmvPpQAAAAAFxYAFESkW2FnrJlkwmQZjTXL1IVM95lW/f///wK76QAAAAAAABYAFB33sq8WtoOlpvUpCvoWbxJJl5rhECcAAAAAAAAXqRTFhAlcZBMRkG4iAustDT6iSw6wkIcAAAAAAQEgECcAAAAAAAAXqRTFhAlcZBMRkG4iAustDT6iSw6wkIcBBxcWABSLInl3egAHj/E1xymd9vWdJ7knmQEIawJHMEQCIAkPXe9sdpRjSDTjJ0gIrpwGGIWJby9xSd1rS9hPe1f0AiAJgqR7PL3G/MXyUu4KZdS1Z2O14fjxstF43k634u+4GAEhA/2o8s1fdIIUPtMyDtplUnd3xmIb8GI2pBgmOFjWMaHmAAEAcgIAAAAB97Oqk3E4gOTA0WF9lUti+6FDGqao08nCXJduFzxy4s8AAAAAAP3///8CECcAAAAAAAAXqRRcl9Sf+c1s0P5r5CGoefIJLL2g+YcdwgAAAAAAABYAFJQPdrykhhpou8p1nGgQ8V+jy+UPAAAAAAEBIBAnAAAAAAAAF6kUXJfUn/nNbND+a+QhqHnyCSy9oPmHAQcXFgAUyRIBhZwlI4RLT6NDHluovlrN3iABCGsCRzBEAiAOzRsNZ+2Et+VGCY/nXWO7WxGI3u39kpi025cUaJXQJgIgL6KtMqPfAwXGktQFWr9SNnOrHF2xjvKQI2VdeuQbxt0BIQIs+YA2N8B5O6nF4SgVEG765xfHZFKrLiKbjZuo8/9vPAAiAgKvIfgAREwuU3M7rbN8YQrVwMyBFBzOYjLoL8BTK7QnOBAStOnGAAAAgAEAAIDDAACAAAA='
        self.assertEqual(self.to_base64(psbt), expected)

        # Finalizing clears keypaths and signatures.
        # Ensure later added values continue to be validated.
        inp = psbt.contents.inputs[0]
        bad_pub, bad_pub_len = make_cbuffer('00' * 33)
        sig, sig_len = make_cbuffer('30' * 8)
        ret = wally_psbt_input_add_signature(inp, bad_pub, bad_pub_len, sig, sig_len)
        self.assertEqual(ret, WALLY_EINVAL)
        pub, pub_len = make_cbuffer('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
        fp, fp_len = make_cbuffer('00' * 4)
        path = (c_uint * 1)(0)
        ret = wally_psbt_input_keypath_add(inp, pub, pub_len, fp, fp_len, path, 1)
        self.assertEqual(ret, WALLY_OK)

    def test_finalize_taproot(self):
        """Finalizing a taproot input clears its key and script path fields"""
        # A key path signed tr(A,pk(B)) input, with all BIP-371 input fields
        b64 = (
            'cHNidP8BAgQCAAAAAQQBAQEFAQEBBgEDAfsEAgAAAAABASughgEAAAAAACJRIM1d4GeBjJtxV0v0Qpnr'
            'mU5yeu0KABAOscoL5hLo+q8dAQ4gq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6sBDwQAAAAA'
            'ARAEAAAAAAETQBUCOuY3LxiO3HdmmmnOCUcfNmlPXgGsXePFnJUU4PiScSVYzi3sswUjjhnK8hZMZF+6'
            '/BSVqbTZ+Wix1jQO3WFBFLpBq3Hp6LwfYFKPFETLhtwPs+94LM022gHjD+y0Dedk3NVFPtu524iPPDG4'
            'fBUM+JRlXZVlgiw42fB1OUt3nhpAqvAC/X4LFnvmtlfTsBUw9LhqaA5wXh5hffC6dNMuaqp9Wv/UFKn7'
            'vKm92wNyZJ7tKadzBN5+KsMOYLbY/avV/iIVwb8Q4+5f9eAeVvocytyYuufygsor7bLH7TC83hUqOYjY'
            'IyC6Qatx6ei8H2BSjxREy4bcD7PveCzNNtoB4w/stA3nZKzAIRa/EOPuX/XgHlb6HMrcmLrn8oLKK+2y'
            'x+0wvN4VKjmI2AUAgkt2ByEWukGrcenovB9gUo8URMuG3A+z73gszTbaAeMP7LQN52QlAdzVRT7buduI'
            'jzwxuHwVDPiUZV2VZYIsONnwdTlLd54awDryRgEXIL8Q4+5f9eAeVvocytyYuufygsor7bLH7TC83hUq'
            'OYjYARgg3NVFPtu524iPPDG4fBUM+JRlXZVlgiw42fB1OUt3nhoAAQMI6AMAAAAAAAABBBYAFKurq6ur'
            'q6urq6urq6urq6urq6urAA==')
        psbt = self.parse_base64(b64)
        inp = psbt.contents.inputs[0]
        self.assertEqual(inp.taproot_leaf_scripts.num_items, 1)
        self.assertEqual(inp.taproot_leaf_signatures.num_items, 1)
        self.assertEqual(wally_psbt_finalize(psbt, 0), WALLY_OK)
        ret, is_finalized = wally_psbt_is_finalized(psbt)
        self.assertEqual((ret, is_finalized), (WALLY_OK, 1))
        for m in [inp.taproot_leaf_scripts, inp.taproot_leaf_signatures,
                  inp.taproot_leaf_hashes, inp.taproot_leaf_paths]:
            self.assertEqual(m.num_items, 0)
        for field_type in [0x13, 0x17, 0x18]: # TAP_KEY_SIG/INTERNAL_KEY/MERKLE_ROOT
            ret, idx = wally_map_find_integer(byref(inp.psbt_fields), field_type)
            self.assertEqual((ret, idx), (WALLY_OK, 0))
        wally_psbt_free(psbt)

    def test_taproot_tree(self):
        """Test output taproot tree validation"""
        psbt = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 0, 1, 0, 0, psbt))
        tx_out = pointer(wally_tx_output())
        ret = wally_tx_output_init_alloc(1000, b'\x51', 1, tx_out)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_output_at(psbt, 0, 0, tx_out))
        tree = byref(psbt.contents.outputs[0].taproot_tree)

        leaf = lambda depth, ver, script: bytes([depth, ver, len(script)]) + script
        for value in [
            b'',                                   # Empty
            bytes([0, 0xc0]),                      # Truncated leaf
            leaf(129, 0xc0, b'\x51'),              # Too deep
            leaf(0, 0xc1, b'\x51'),                # Odd leaf version
            leaf(0, 0x50, b'\x51'),                # Annex tag as leaf version
            leaf(0, 0xc0, b'\x51')[:-1],           # Truncated script
            leaf(0, 0xc0, b'\x51') + b'\x00',      # Trailing truncated leaf
            bytes([0, 0xc0, 0xfd, 0x01]),          # Truncated script length
            ]:
            ret = wally_map_add_integer(tree, 1, value, len(value))
            self.assertEqual(ret, WALLY_EINVAL)

        value = leaf(1, 0xc0, b'\x51') + leaf(2, 0xc0, b'') + leaf(128, 0xc0, b'\x52')
        ret = wally_map_add_integer(tree, 1, value, len(value))
        self.assertEqual(ret, WALLY_OK)

        # Valid trees round-trip, invalid trees fail to parse
        b64 = self.to_base64(psbt)
        psbt2 = self.parse_base64(b64)
        self.assertEqual(self.to_base64(psbt2), b64)
        wally_psbt_free(psbt2)
        ret, length = wally_psbt_get_length(psbt, 0)
        self.assertEqual(ret, WALLY_OK)
        buf, buf_len = make_cbuffer('00' * length)
        self.assertEqual(wally_psbt_to_bytes(psbt, 0, buf, buf_len), (WALLY_OK, length))
        invalid = bytes(buf).replace(value, leaf(1, 0xc1, b'\x51') + value[4:])
        ret = wally_psbt_from_bytes(invalid, len(invalid), 0, pointer(wally_psbt()))
        self.assertEqual(ret, WALLY_EINVAL)
        wally_psbt_free(psbt)

    def get_id(self, psbt):
        buf, buf_len = make_cbuffer('00' * 32)
        self.assertEqual(wally_psbt_get_id(psbt, 0, buf, buf_len), WALLY_OK)
        return h(buf)

    def check_silent_payment_id(self, psbt):
        """Check the BIP-375 id of a PSBT with unresolved silent payment outputs"""
        unresolved_id = self.get_id(psbt)

        # The id does not change once the output scripts are computed
        p2tr = b'\x51\x20' + b'\x01' * 32
        resolved = pointer(wally_psbt())
        self.assertEqual(wally_psbt_clone_alloc(psbt, 0, resolved), WALLY_OK)
        # BIP-375 defines the id with each silent payment output's script
        # replaced by a zero byte followed by its silent payment code
        as_scripts = pointer(wally_psbt())
        self.assertEqual(wally_psbt_clone_alloc(psbt, 0, as_scripts), WALLY_OK)
        sp_outputs = []
        for i in range(psbt.contents.num_outputs):
            out = byref(psbt.contents.outputs[i])
            keys, keys_len = make_cbuffer('00' * WALLY_SILENT_PAYMENT_KEYS_LEN)
            ret, written = wally_psbt_output_get_sp_v0_info(out, keys, keys_len)
            self.assertEqual(ret, WALLY_OK)
            if written and not psbt.contents.outputs[i].script:
                sp_outputs.append(i)
                out = byref(resolved.contents.outputs[i])
                self.assertEqual(wally_psbt_output_set_script(out, p2tr, len(p2tr)), WALLY_OK)
                out = byref(as_scripts.contents.outputs[i])
                script = b'\x00' + bytes(keys)
                self.assertEqual(wally_psbt_output_set_script(out, script, len(script)), WALLY_OK)
                self.assertEqual(wally_psbt_output_clear_sp_v0_info(out), WALLY_OK)
        self.assertNotEqual(sp_outputs, [])
        self.assertEqual(self.get_id(resolved), unresolved_id)
        self.assertEqual(self.get_id(as_scripts), unresolved_id)

        # Combining fills in the computed scripts, from either side
        for dst, src in [(psbt, resolved), (resolved, psbt)]:
            combined = pointer(wally_psbt())
            self.assertEqual(wally_psbt_clone_alloc(dst, 0, combined), WALLY_OK)
            self.assertEqual(wally_psbt_combine(combined, src), WALLY_OK)
            self.assertEqual(self.to_base64(combined), self.to_base64(resolved))
            wally_psbt_free(combined)

        # Two different computed scripts cannot be combined
        other = pointer(wally_psbt())
        self.assertEqual(wally_psbt_clone_alloc(resolved, 0, other), WALLY_OK)
        p2tr = b'\x51\x20' + b'\x02' * 32
        out = byref(other.contents.outputs[sp_outputs[0]])
        self.assertEqual(wally_psbt_output_set_script(out, p2tr, len(p2tr)), WALLY_OK)
        self.assertEqual(self.get_id(other), unresolved_id)
        self.assertEqual(wally_psbt_combine(other, resolved), WALLY_EINVAL)
        for p in [resolved, as_scripts, other]:
            wally_psbt_free(p)

    def get_map_value(self, map_ref, key):
        ret, index = wally_map_find(map_ref, key, len(key))
        self.assertEqual(ret, WALLY_OK)
        if not index:
            return None
        buf, buf_len = make_cbuffer('00' * 64)
        ret, written = wally_map_get_item(map_ref, index - 1, buf, buf_len)
        self.assertEqual(ret, WALLY_OK)
        return bytes(buf)[:written]

    def test_silent_payment_shares(self):
        """Test BIP-375 ECDH share and DLEQ proof fields"""
        # bip-0375/bip375_test_vectors.json from bitcoin/bips commit a34f044b
        with open(root_dir + 'src/data/bip375_vectors.json', 'r') as f:
            cases = json.load(f)

        num_global, num_input = 0, 0
        for case in cases['valid']:
            psbt = self.parse_base64(case['psbt'])
            b64 = self.to_base64(psbt)
            psbt2 = self.parse_base64(b64)
            self.assertEqual(self.to_base64(psbt2), b64)
            wally_psbt_free(psbt2)
            for proof in case['supplementary'].get('sp_proofs', []):
                scan = bytes.fromhex(proof['scan_key'])
                if 'input_index' in proof:
                    p = psbt.contents.inputs[proof['input_index']]
                    num_input += 1
                else:
                    p = psbt.contents
                    num_global += 1
                share = self.get_map_value(byref(p.sp_ecdh_shares), scan)
                dleq = self.get_map_value(byref(p.sp_dleq_proofs), scan)
                self.assertEqual(share, bytes.fromhex(proof['ecdh_share']))
                self.assertEqual(dleq, bytes.fromhex(proof['dleq_proof']))
            wally_psbt_free(psbt)
        self.assertGreater(num_global, 0)
        self.assertGreater(num_input, 0)

        invalid = [
            'psbt structure: incorrect byte length for PSBT_IN_SP_ECDH_SHARE field',
            'psbt structure: incorrect byte length for PSBT_IN_SP_DLEQ field',
        ]
        for case in cases['invalid']:
            if case['description'] in invalid:
                self.parse_base64(case['psbt'], WALLY_EINVAL)
                invalid.remove(case['description'])
        self.assertEqual(invalid, [])

        # The maps only accept valid scan keys, shares and proofs
        psbt = pointer(wally_psbt())
        self.assertEqual(wally_psbt_init_alloc(2, 1, 0, 0, 0, psbt), WALLY_OK)
        scan = bytes.fromhex('027a487fc19fb769877b8742d6ea18118f3c4e72b1ea8c6de602a7ad4a41dbe068')
        share = bytes.fromhex('02d3262723352607e84fcaf7651f8d2d637e020aea86dfad80d306cd4f48cfcc62')
        shares, proofs = byref(psbt.contents.sp_ecdh_shares), byref(psbt.contents.sp_dleq_proofs)
        for key, val in [(scan[:-1], share), (b'\x04' + scan[1:], share),
                         (scan, share[:-1]), (scan, b'\x04' + share[1:])]:
            self.assertEqual(wally_map_add(shares, key, len(key), val, len(val)), WALLY_EINVAL)
        for key, val in [(scan[:-1], bytes(64)), (scan, bytes(63)), (scan, bytes(65))]:
            self.assertEqual(wally_map_add(proofs, key, len(key), val, len(val)), WALLY_EINVAL)
        self.assertEqual(wally_map_add(shares, scan, len(scan), share, len(share)), WALLY_OK)
        self.assertEqual(wally_map_add(proofs, scan, len(scan), bytes(64), 64), WALLY_OK)
        wally_psbt_free(psbt)

        # Share and proof fields are v2 only; BIP-373 input fields stay unknown
        def build(version, num_inputs):
            psbt = pointer(wally_psbt())
            self.assertEqual(wally_psbt_init_alloc(version, num_inputs, 0, 0, 0, psbt), WALLY_OK)
            txhash = b'\x01' * 32 # A null prevout is refused
            if version == 0:
                tx = pointer(wally_tx())
                self.assertEqual(wally_tx_init_alloc(2, 0, num_inputs, 0, tx), WALLY_OK)
                for i in range(num_inputs):
                    ret = wally_tx_add_raw_input(tx, txhash, 32, i, 0xffffffff, None, 0, None, 0)
                    self.assertEqual(ret, WALLY_OK)
                self.assertEqual(wally_psbt_set_global_tx(psbt, tx), WALLY_OK)
                wally_tx_free(tx)
            else:
                for i in range(num_inputs):
                    tx_in = pointer(wally_tx_input())
                    ret = wally_tx_input_init_alloc(txhash, 32, i, 0xffffffff, None, 0, None, tx_in)
                    self.assertEqual(ret, WALLY_OK)
                    self.assertEqual(wally_psbt_add_tx_input_at(psbt, i, 0, tx_in), WALLY_OK)
            ret, length = wally_psbt_get_length(psbt, 0)
            self.assertEqual(ret, WALLY_OK)
            buf, buf_len = make_cbuffer('00' * length)
            self.assertEqual(wally_psbt_to_bytes(psbt, 0, buf, buf_len), (WALLY_OK, length))
            wally_psbt_free(psbt)
            return bytes(buf)

        g_share = b'\x22\x07' + scan + b'\x21' + share
        g_proof = b'\x22\x08' + scan + b'\x40' + bytes(64)
        i_share = b'\x22\x1d' + scan + b'\x21' + share
        i_proof = b'\x22\x1e' + scan + b'\x40' + bytes(64)
        musig = b'\x22\x1b' + scan + b'\x21' + share # BIP-373 MuSig2 public nonce

        # With one empty input and no outputs, a v0 PSBT ends with the global
        # separator then the input separator. A v2 PSBT with no inputs ends with
        # the global separator; with one input and no outputs, the input separator.
        v0, v2_globals, v2_input = build(0, 1), build(2, 0), build(2, 1)
        for raw, expected in [
            (v0[:-2] + g_share + v0[-2:], WALLY_EINVAL),
            (v0[:-2] + g_proof + v0[-2:], WALLY_EINVAL),
            (v0[:-1] + i_share + v0[-1:], WALLY_EINVAL),
            (v0[:-1] + i_proof + v0[-1:], WALLY_EINVAL),
            (v0[:-1] + musig + v0[-1:], WALLY_OK),
            (v2_globals[:-1] + g_share + g_proof + v2_globals[-1:], WALLY_OK),
            (v2_input[:-1] + i_share + i_proof + musig + v2_input[-1:], WALLY_OK),
            ]:
            psbt = pointer(wally_psbt())
            self.assertEqual(wally_psbt_from_bytes(raw, len(raw), 0, psbt), expected)
            if expected != WALLY_OK:
                continue
            p = psbt.contents.inputs[0] if psbt.contents.num_inputs else psbt.contents
            num_sp = 0 if raw.startswith(v0[:-2]) else 1
            self.assertEqual((p.sp_ecdh_shares.num_items, p.sp_dleq_proofs.num_items),
                             (num_sp, num_sp))
            if psbt.contents.num_inputs:
                self.assertEqual(p.unknowns.num_items, 1) # MuSig2 field
            b64 = self.to_base64(psbt)
            psbt2 = self.parse_base64(b64)
            self.assertEqual(self.to_base64(psbt2), b64)
            wally_psbt_free(psbt2)
            wally_psbt_free(psbt)

    def fix_sp_prevouts(self, psbt):
        """Make P2WPKH prevout scripts commit to their BIP32 derivation keys.

        The BIP-375 vectors' P2WPKH prevout scripts do not hash to the input
        public keys. wally requires that they do, as a receiver finds the
        payment from the key that is actually spent. Output scripts depend
        on the keys and outpoints only, so this does not change them.
        """
        for i in range(psbt.contents.num_inputs):
            inp = psbt.contents.inputs[i]
            utxo = inp.witness_utxo
            if not utxo or not inp.keypaths.num_items:
                continue
            script = string_at(utxo.contents.script, utxo.contents.script_len)
            item = inp.keypaths.items[0]
            pub_key = string_at(item.key, item.key_len)
            if script[:2] != b'\x00\x14' or len(pub_key) != 33:
                continue
            h, h_len = make_cbuffer('00' * 20)
            self.assertEqual(wally_hash160(pub_key, 33, h, h_len), WALLY_OK)
            tx_out = pointer(wally_tx_output())
            script = b'\x00\x14' + bytes(h)
            ret = wally_tx_output_init_alloc(utxo.contents.satoshi, script, len(script), tx_out)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(wally_psbt_input_set_witness_utxo(byref(inp), tx_out), WALLY_OK)
            wally_tx_output_free(tx_out)

    def get_sp_scripts(self, psbt):
        """Return {output index: script} for the silent payment outputs"""
        scripts = {}
        for i in range(psbt.contents.num_outputs):
            out = psbt.contents.outputs[i]
            if wally_psbt_output_get_sp_v0_info_len(byref(out))[1]:
                scripts[i] = string_at(out.script, out.script_len) if out.script else None
        return scripts

    def test_silent_payment_scripts(self):
        """Test computing BIP-375 silent payment output scripts"""
        # bip-0375/bip375_test_vectors.json from bitcoin/bips commit a34f044b
        with open(root_dir + 'src/data/bip375_vectors.json', 'r') as f:
            cases = json.load(f)
        txmod_all = 0x3 # WALLY_PSBT_TXMOD_INPUTS | WALLY_PSBT_TXMOD_OUTPUTS

        num_computed = 0
        for case in cases['valid']:
            if case.get('checks') == ['input_eligibility']:
                # Only checks that a bare OP_2 is not a segwit v2 input; with
                # no eligible input, no script can be computed
                continue
            psbt = self.parse_base64(case['psbt'])
            self.fix_sp_prevouts(psbt)
            scripts = self.get_sp_scripts(psbt)
            b64 = self.to_base64(psbt)
            ret = wally_psbt_compute_sp_scripts(psbt, 0)
            if None not in scripts.values():
                # Every script is present: they check out, and nothing changes
                self.assertEqual(ret, WALLY_OK, case['description'])
                self.assertEqual(self.to_base64(psbt), b64)
                # With the scripts removed, the same scripts are computed
                for i in scripts:
                    out = byref(psbt.contents.outputs[i])
                    self.assertEqual(wally_psbt_output_set_script(out, None, 0), WALLY_OK)
                self.assertEqual(wally_psbt_set_tx_modifiable_flags(psbt, txmod_all), WALLY_OK)
                self.assertEqual(wally_psbt_compute_sp_scripts(psbt, 0), WALLY_OK)
                self.assertEqual(self.get_sp_scripts(psbt), scripts, case['description'])
                self.assertEqual(psbt.contents.tx_modifiable_flags & txmod_all, 0)
                if scripts:
                    num_computed += 1
                # Modifiable flags cannot be set once the scripts are
                self.assertEqual(wally_psbt_set_tx_modifiable_flags(psbt, txmod_all), WALLY_OK)
                self.assertEqual(wally_psbt_compute_sp_scripts(psbt, 0), WALLY_EINVAL)
            else:
                # In progress with shares missing: fails and changes nothing
                self.assertEqual(ret, WALLY_EINVAL, case['description'])
                self.assertEqual(self.to_base64(psbt), b64)
            wally_psbt_free(psbt)
        self.assertGreater(num_computed, 10)

        # Every invalid vector is rejected by parsing or by computing
        for case in cases['invalid']:
            psbt = pointer(wally_psbt())
            ret = wally_psbt_from_base64(case['psbt'], 0, psbt)
            if ret == WALLY_OK:
                self.fix_sp_prevouts(psbt)
                ret = wally_psbt_compute_sp_scripts(psbt, 0)
                wally_psbt_free(psbt)
            self.assertEqual(ret, WALLY_EINVAL, case['description'])

        # An input key that does not hash to its prevout script is refused
        case = [c for c in cases['valid'] if 'single-signer using global' in c['description']][0]
        psbt = self.parse_base64(case['psbt'])
        self.assertEqual(wally_psbt_compute_sp_scripts(psbt, 0), WALLY_EINVAL)
        self.fix_sp_prevouts(psbt)
        self.assertEqual(wally_psbt_compute_sp_scripts(psbt, 0), WALLY_OK)

        # Invalid arguments
        self.assertEqual(wally_psbt_compute_sp_scripts(None, 0), WALLY_EINVAL)
        self.assertEqual(wally_psbt_compute_sp_scripts(psbt, 1), WALLY_EINVAL)
        wally_psbt_free(psbt)

        # Finalized inputs no longer have keypaths or partial signatures:
        # the key comes from the final witness or scriptSig instead
        sig = bytes.fromhex('30' + '00' * 70 + '01')
        for desc in ['one P2PKH input single-signer',
                     'one P2WPKH input / two mixed outputs']:
            case = [c for c in cases['valid'] if desc in c['description']][0]
            psbt = self.parse_base64(case['psbt'])
            self.fix_sp_prevouts(psbt)
            scripts = self.get_sp_scripts(psbt)
            inp = psbt.contents.inputs[0]
            item = inp.keypaths.items[0]
            pub_key = string_at(item.key, item.key_len)
            wally_map_clear(byref(inp.keypaths))
            wally_map_clear(byref(inp.signatures))
            self.assertEqual(wally_psbt_compute_sp_scripts(psbt, 0), WALLY_EINVAL)
            if 'P2PKH' in desc:
                script_sig = bytes([len(sig)]) + sig + bytes([len(pub_key)]) + pub_key
                ret = wally_psbt_input_set_final_scriptsig(byref(inp), script_sig, len(script_sig))
            else:
                witness = pointer(wally_tx_witness_stack())
                self.assertEqual(wally_tx_witness_stack_init_alloc(2, witness), WALLY_OK)
                for w in [sig, pub_key]:
                    self.assertEqual(wally_tx_witness_stack_add(witness, w, len(w)), WALLY_OK)
                ret = wally_psbt_input_set_final_witness(byref(inp), witness)
                wally_tx_witness_stack_free(witness)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(wally_psbt_compute_sp_scripts(psbt, 0), WALLY_OK, desc)
            self.assertEqual(self.get_sp_scripts(psbt), scripts)
            wally_psbt_free(psbt)

    def test_silent_payment_outputs(self):
        """Test BIP-375 silent payment output fields"""
        # bip-0375/bip375_test_vectors.json from bitcoin/bips commit a34f044b
        with open(root_dir + 'src/data/bip375_vectors.json', 'r') as f:
            cases = json.load(f)

        num_unresolved = 0
        for case in cases['valid']:
            psbt = self.parse_base64(case['psbt'])
            b64 = self.to_base64(psbt)
            psbt2 = self.parse_base64(b64)
            self.assertEqual(self.to_base64(psbt2), b64)
            wally_psbt_free(psbt2)
            unresolved = False
            for i in range(psbt.contents.num_outputs):
                out = byref(psbt.contents.outputs[i])
                ret, info_len = wally_psbt_output_get_sp_v0_info_len(out)
                self.assertEqual(ret, WALLY_OK)
                self.assertIn(info_len, [0, WALLY_SILENT_PAYMENT_KEYS_LEN])
                if info_len and not psbt.contents.outputs[i].script:
                    unresolved = True
            if unresolved:
                # No transaction can be built until every script is computed
                num_unresolved += 1
                tx = pointer(wally_tx())
                ret = wally_psbt_extract(psbt, WALLY_PSBT_EXTRACT_NON_FINAL, tx)
                self.assertEqual(ret, WALLY_EINVAL)
                self.check_silent_payment_id(psbt)
            wally_psbt_free(psbt)
        self.assertEqual(num_unresolved, 3)

        invalid = [
            'psbt structure: missing PSBT_OUT_SP_V0_INFO field when PSBT_OUT_SP_V0_LABEL set',
            'psbt structure: incorrect byte length for PSBT_OUT_SP_V0_LABEL field',
            'psbt structure: incorrect byte length for PSBT_OUT_SP_V0_INFO field',
            'psbt structure: missing PSBT_OUT_SCRIPT field when sending to non-sp output',
        ]
        for case in cases['invalid']:
            if case['description'] in invalid:
                self.parse_base64(case['psbt'], WALLY_EINVAL)
                invalid.remove(case['description'])
        self.assertEqual(invalid, [])

        # An output may omit its script only if it has a silent payment code
        psbt = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 0, 1, 0, 0, psbt))
        tx_out = pointer(wally_tx_output())
        ret = wally_tx_output_init_alloc(1000, b'\x51', 1, tx_out)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_output_at(psbt, 0, 0, tx_out))
        out = byref(psbt.contents.outputs[0])
        keys = bytes.fromhex('0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4'
                             '025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36')
        for bad in [keys[:-1], keys + b'\x00', b'\x04' + keys[1:], keys[:33] + b'\x04' + keys[34:]]:
            self.assertEqual(wally_psbt_output_set_sp_v0_info(out, bad, len(bad)), WALLY_EINVAL)
        self.assertEqual(wally_psbt_output_set_sp_v0_info(out, keys, len(keys)), WALLY_OK)
        buf, buf_len = make_cbuffer('00' * len(keys))
        ret, written = wally_psbt_output_get_sp_v0_info(out, buf, buf_len)
        self.assertEqual((ret, written, bytes(buf)), (WALLY_OK, len(keys), keys))

        # BIP-375 fields are v2 only: a code must not survive a conversion to v0
        self.assertEqual(wally_psbt_output_set_script(out, b'\x51', 1), WALLY_OK)
        self.assertEqual(wally_psbt_set_version(psbt, 0, 0), WALLY_EINVAL)
        self.assertEqual(psbt.contents.version, 2)

        self.assertEqual(wally_psbt_output_set_script(out, None, 0), WALLY_OK)
        b64 = self.to_base64(psbt)
        psbt2 = self.parse_base64(b64)
        self.assertEqual(self.to_base64(psbt2), b64)
        self.assertEqual(psbt2.contents.outputs[0].script_len, 0)
        wally_psbt_free(psbt2)

        self.assertEqual(wally_psbt_output_clear_sp_v0_info(out), WALLY_OK)
        ret, written = wally_psbt_output_get_sp_v0_info_len(out)
        self.assertEqual((ret, written), (WALLY_OK, 0))
        self.assertEqual(wally_psbt_to_base64(psbt, 0), (WALLY_EINVAL, None))
        wally_psbt_free(psbt)

        # Signing is refused while a silent payment script is missing
        case = [c for c in cases['valid'] if c['description'].startswith('in progress: one P2TR')][0]
        psbt = self.parse_base64(case['psbt'])
        self.assertEqual(wally_psbt_sign(psbt, b'\x01' * 32, 32, 0), WALLY_EINVAL)
        wally_psbt_free(psbt)

        # Clearing the code of a labelled output cannot write a lone label
        case = [c for c in cases['valid'] if 'label=0 convention' in c['description']][0]
        psbt = self.parse_base64(case['psbt'])
        self.assertEqual(wally_psbt_output_clear_sp_v0_info(byref(psbt.contents.outputs[1])), WALLY_OK)
        self.assertEqual(wally_psbt_to_base64(psbt, 0), (WALLY_EINVAL, None))
        wally_psbt_free(psbt)

        # Silent payment fields are v2 only; BIP-373 field 0x08 stays unknown
        def with_output_fields(version, fields):
            psbt = pointer(wally_psbt())
            self.assertEqual(wally_psbt_init_alloc(version, 0, 1, 0, 0, psbt), WALLY_OK)
            if version == 0:
                tx = pointer(wally_tx())
                self.assertEqual(wally_tx_init_alloc(2, 0, 0, 1, tx), WALLY_OK)
                self.assertEqual(wally_tx_add_raw_output(tx, 1000, b'\x51', 1, 0), WALLY_OK)
                self.assertEqual(wally_psbt_set_global_tx(psbt, tx), WALLY_OK)
                wally_tx_free(tx)
            else:
                tx_out = pointer(wally_tx_output())
                self.assertEqual(wally_tx_output_init_alloc(1000, b'\x51', 1, tx_out), WALLY_OK)
                self.assertEqual(wally_psbt_add_tx_output_at(psbt, 0, 0, tx_out), WALLY_OK)
                # BIP-375: Not modifiable once a silent payment script is set
                self.assertEqual(wally_psbt_set_tx_modifiable_flags(psbt, 0), WALLY_OK)
            ret, length = wally_psbt_get_length(psbt, 0)
            self.assertEqual(ret, WALLY_OK)
            buf, buf_len = make_cbuffer('00' * length)
            self.assertEqual(wally_psbt_to_bytes(psbt, 0, buf, buf_len), (WALLY_OK, length))
            wally_psbt_free(psbt)
            return bytes(buf)[:-1] + b''.join(fields) + b'\x00' # Before the last separator

        info = b'\x01\x09' + bytes([len(keys)]) + keys
        label = b'\x01\x0a\x04' + bytes(4)
        musig = [b'\x22\x08' + keys[:33] + bytes([len(keys)]) + keys,
                 b'\x22\x08' + keys[33:] + bytes([len(keys)]) + keys]
        for version, fields, expected, num_unknowns in [
            (0, [info], WALLY_EINVAL, 0),
            (0, [info, label], WALLY_EINVAL, 0),
            (0, musig, WALLY_OK, 2),
            (2, [info, label], WALLY_OK, 0),
            (2, musig, WALLY_OK, 2),
            ]:
            raw = with_output_fields(version, fields)
            psbt = pointer(wally_psbt())
            self.assertEqual(wally_psbt_from_bytes(raw, len(raw), 0, psbt), expected)
            if expected == WALLY_OK:
                self.assertEqual(psbt.contents.outputs[0].unknowns.num_items, num_unknowns)
                b64 = self.to_base64(psbt)
                psbt2 = self.parse_base64(b64)
                self.assertEqual(self.to_base64(psbt2), b64)
                wally_psbt_free(psbt2)
                wally_psbt_free(psbt)

    def test_psbt(self):
        """Test creating and modifying various PSBT fields"""
        tx = pointer(wally_tx())
        self.assertEqual(wally_tx_init_alloc(2, 0, 2, 2, tx), WALLY_OK)
        txid, txid_len = make_cbuffer('11' * 32)
        self.assertEqual(wally_tx_add_raw_input(tx, txid, txid_len, 0,
                                                0xffffffff, None, 0, None, 0), WALLY_OK)
        psbt = pointer(wally_psbt())
        for ver, result in [
            (0, 'cHNidP8A'),
            (1, None),
            (2, 'cHNidP8BAgQCAAAAAQQBAAEFAQAB+wQCAAAAAA=='),
            (3, None) ]:
            ret = wally_psbt_init_alloc(ver, 3, 3, 0, 0, psbt)
            self.assertEqual(ret, WALLY_OK if result else WALLY_EINVAL)
            if result:
                self.assertEqual(self.to_base64(psbt, MOD_NONE), result)

                # Global tx can only be set on a version 0 PSBT
                ret = wally_psbt_set_global_tx(psbt, tx)
                self.assertEqual(ret, WALLY_OK if ver == 0 else WALLY_EINVAL)

                if ver == 0:
                    # Ensure inputs from global tx have been initialized, by
                    # ensuring the keypath maps validation fn is set
                    self.assertIsNotNone(psbt.contents.inputs[0].keypaths.verify_fn)

        # Create a v2 PSBT
        wally_psbt_init_alloc(2, 0, 0, 0, 0, psbt)

        self.assertEqual(wally_psbt_set_tx_version(psbt, 123), WALLY_OK)
        self.assertEqual(self.to_base64(psbt, MOD_NONE), 'cHNidP8BAgR7AAAAAQQBAAEFAQAB+wQCAAAAAA==')

        self.assertEqual(wally_psbt_set_fallback_locktime(psbt, 456), WALLY_OK)
        self.assertEqual(self.to_base64(psbt, MOD_NONE), 'cHNidP8BAgR7AAAAAQMEyAEAAAEEAQABBQEAAfsEAgAAAAA=')

        self.assertEqual(wally_psbt_clear_fallback_locktime(psbt), WALLY_OK)
        self.assertEqual(self.to_base64(psbt, MOD_NONE), 'cHNidP8BAgR7AAAAAQQBAAEFAQAB+wQCAAAAAA==')

        self.assertEqual(wally_psbt_set_tx_modifiable_flags(psbt, 3), WALLY_OK)
        self.assertEqual(self.to_base64(psbt), 'cHNidP8BAgR7AAAAAQQBAAEFAQABBgEDAfsEAgAAAAA=')

        # Create an input
        tx_input = pointer(wally_tx_input())

        txhash, txhash_len = make_cbuffer('e7f25add4560021c77c4944f92739025fddbf99816d79c06d219268ca9f4b7e7')
        ret = wally_tx_input_init_alloc(txhash, txhash_len, 5, 6, b'\x59', 1, None, tx_input)
        self.assertEqual(WALLY_OK, ret)
        ret = wally_psbt_add_tx_input_at(psbt, 0, 0, tx_input)
        self.assertEqual(WALLY_OK, ret)
        ret, base64 = wally_psbt_to_base64(psbt, 0)
        self.assertEqual(WALLY_OK, ret)
        self.assertEqual('cHNidP8BAgR7AAAAAQQBAQEFAQABBgEDAfsEAgAAAAABDiDn8lrdRWACHHfElE+Sc5Al/dv5mBbXnAbSGSaMqfS35wEPBAUAAAABEAQGAAAAAA==', base64)

        ret = wally_psbt_input_set_required_lockheight(psbt.contents.inputs[0], 499999999)
        self.assertEqual(WALLY_OK, ret)
        ret, base64 = wally_psbt_to_base64(psbt, 0)
        self.assertEqual(WALLY_OK, ret)
        self.assertEqual('cHNidP8BAgR7AAAAAQQBAQEFAQABBgEDAfsEAgAAAAABDiDn8lrdRWACHHfElE+Sc5Al/dv5mBbXnAbSGSaMqfS35wEPBAUAAAABEAQGAAAAARIE/2TNHQA=', base64)

        tx_output = pointer(wally_tx_output())

        wally_tx_output_init_alloc(1234, b'\x59\x59', 2, tx_output)
        self.assertEqual(WALLY_OK, ret)
        ret = wally_psbt_add_tx_output_at(psbt, 0, 0, tx_output)
        self.assertEqual(WALLY_OK, ret)

        ret, base64 = wally_psbt_to_base64(psbt, 0)
        self.assertEqual(WALLY_OK, ret)
        self.assertEqual('cHNidP8BAgR7AAAAAQQBAQEFAQEBBgEDAfsEAgAAAAABDiDn8lrdRWACHHfElE+Sc5Al/dv5mBbXnAbSGSaMqfS35wEPBAUAAAABEAQGAAAAARIE/2TNHQABAwjSBAAAAAAAAAEEAllZAA==', base64)

    def test_global_tx_init(self):
        """Test that PSBTs created from a tx have initialized in/outputs"""
        tx = pointer(wally_tx())
        self.assertEqual(WALLY_OK, wally_tx_init_alloc(2, 0, 1, 1, tx))
        txhash, txhash_len = make_cbuffer('11' * 32)
        tx_in = pointer(wally_tx_input())
        ret = wally_tx_input_init_alloc(txhash, txhash_len, 0, 0xffffffff, None, 0, None, tx_in)
        self.assertEqual(WALLY_OK, ret)
        self.assertEqual(WALLY_OK, wally_tx_add_input(tx, tx_in))
        tx_out = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK, wally_tx_output_init_alloc(1234, b'\x59\x59', 2, tx_out))
        self.assertEqual(WALLY_OK, wally_tx_add_output(tx, tx_out))

        pk, pk_len = make_cbuffer('038575eb35e18fb168a913d8b49af50204f4f73627f6f7884f1be11e354664de8b')
        fpr, fpr_len = make_cbuffer('00' * 4)
        path, path_len = (c_uint32 * 1)(), 1
        bad_preimage, bad_preimage_len = make_cbuffer('ff' + '00' * 32)

        psbt = pointer(wally_psbt())
        for version, num_inputs, num_outputs in [(0, None, None), (2, None, None),
                                                 (0, 0, 0), (0, 1, 1), (0, 2, 2)]:
            if num_inputs is None:
                # Create from the tx
                ret = wally_psbt_from_tx(tx, version, 0, psbt)
                self.assertEqual(WALLY_OK, ret)
            else:
                # Create with pre-allocated in/outputs, then set the tx
                ret = wally_psbt_init_alloc(version, num_inputs, num_outputs, 0, 0, psbt)
                self.assertEqual(WALLY_OK, ret)
                self.assertEqual(WALLY_OK, wally_psbt_set_global_tx(psbt, tx))

            inp = psbt.contents.inputs[0]
            # Keypaths can be added
            for fn in [wally_psbt_add_input_keypath, wally_psbt_add_output_keypath]:
                ret = fn(psbt, 0, pk, pk_len, fpr, fpr_len, path, path_len)
                self.assertEqual(WALLY_OK, ret)
            # Invalid signatures and preimages are rejected
            ret = wally_psbt_input_add_signature(inp, pk, pk_len, b'\x30\x01', 2)
            self.assertEqual(WALLY_EINVAL, ret)
            ret = wally_map_add(byref(inp.preimages), bad_preimage, bad_preimage_len,
                                b'\x00', 1)
            self.assertEqual(WALLY_EINVAL, ret)
            wally_psbt_free(psbt)

    def test_add_tx_in_out_failure(self):
        """Test that failing to add a tx in/output leaves a v0 PSBT unchanged"""
        tx = pointer(wally_tx())
        self.assertEqual(WALLY_OK, wally_tx_init_alloc(2, 0, 1, 1, tx))
        txhash, txhash_len = make_cbuffer('11' * 32)
        tx_in = pointer(wally_tx_input())
        ret = wally_tx_input_init_alloc(txhash, txhash_len, 0, 0xffffffff, None, 0, None, tx_in)
        self.assertEqual(WALLY_OK, ret)
        self.assertEqual(WALLY_OK, wally_tx_add_input(tx, tx_in))
        tx_out = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK, wally_tx_output_init_alloc(1234, b'\x59\x59', 2, tx_out))
        self.assertEqual(WALLY_OK, wally_tx_add_output(tx, tx_out))

        # Make tx_in scriptSig invalid (length with no pointer)
        tx_in.contents.script_len = 5  # Make tx input scripSig invalid
        # Make tx_out amount invalid (would overflow tx total)
        tx_out.contents.satoshi = 2100000000000000

        psbt = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_from_tx(tx, 0, 0, psbt))
        expected = self.to_base64(psbt)
        for index in [0, 1]:
            # Adding tx_in or tx_out now fail
            ret = wally_psbt_add_tx_input_at(psbt, index, 0, tx_in)
            self.assertEqual(WALLY_EINVAL, ret)
            ret = wally_psbt_add_tx_output_at(psbt, index, 0, tx_out)
            self.assertEqual(WALLY_EINVAL, ret)
            self.assertEqual(self.to_base64(psbt), expected)  # PSBT is unchanged
        wally_psbt_free(psbt)
        wally_tx_free(tx)

    def test_invalid_args(self):
        """Test invalid arguments to various PSBT functions"""
        psbt = pointer(wally_psbt())

        # init
        cases = [
            (1, 0, 0, 0, 0, psbt), # Invalid version
            (0, 0, 0, 0, 0xff, psbt), # Invalid flags
            (2, 0, 0, 0, 0xff, psbt), # Invalid flags (v2)
            (0, 0, 0, 0, INIT_PSET, psbt), # v0 PSET
            (0, 0, 0, 0, 0, None), # NULL dest
        ]
        for args in cases:
            self.assertEqual(WALLY_EINVAL, wally_psbt_init_alloc(*args))
        # Too many unknowns: the allocation size would overflow
        too_many = (2 ** (8 * sizeof(c_size_t)) - 1) // sizeof(wally_map_item) + 1
        self.assertEqual(WALLY_ENOMEM, wally_psbt_init_alloc(0, 0, 0, too_many, 0, psbt))

        # psbt_from_base64
        src_base64 = JSON['valid'][0]['psbt']
        src_len = len(src_base64)
        for args in [(None,       0,    psbt),  # NULL base64
                     ('',         0,    psbt),  # Empty base64
                     (src_base64, 0xff, psbt),  # Invalid flags
                     (src_base64, 0,    None)]: # NULL dest
            self.assertEqual(WALLY_EINVAL, wally_psbt_from_base64(*args))

        for args in [(None,       src_len, 0, psbt),   # NULL base64 string, non-0 length
                     (src_base64, 0,       0, psbt)]:  # Non-NULL base64 string, 0 length
            self.assertEqual(WALLY_EINVAL, wally_psbt_from_base64_n(*args))

        self.assertEqual(WALLY_OK, wally_psbt_from_base64(src_base64, 0, psbt))
        self.assertEqual(WALLY_OK, wally_psbt_from_base64_n(src_base64, src_len, 0, psbt))

        # psbt_clone_alloc
        clone = pointer(wally_psbt())
        for args in [(None, 0x0, clone), # NULL src
                     (psbt, 0x1, clone), # Invalid flags
                     (psbt, 0x0, None)]: # NULL dest
            self.assertEqual(WALLY_EINVAL, wally_psbt_clone_alloc(*args))

        # Populate PSBT with one input and output to test various invalid args for taproot keypaths
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt))
        tx_in = pointer(wally_tx_input())
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_input_at(psbt, 0, 0, tx_in))

        tx_output = pointer(wally_tx_output())
        ret = wally_tx_output_init_alloc(1234, b'\x59\x59', 2, tx_output)
        self.assertEqual(WALLY_OK, ret)
        ret = wally_psbt_add_tx_output_at(psbt, 0, 0, tx_output)
        self.assertEqual(WALLY_OK, ret)

        pk, pk_len = make_cbuffer('339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc0')
        mkl, mkl_len = make_cbuffer('00' * 32)
        fpr, fpr_len = make_cbuffer('00' * 4)
        path, path_len = (c_uint32 * 1)(), 1
        i, flags = 0, 0

        invalid_args = [
            (None, i, flags, pk,   pk_len,   mkl,   mkl_len,   fpr, fpr_len,   path, path_len),   # NULL psbt
            (psbt, 1, flags, pk,   pk_len,   mkl,   mkl_len,   fpr, fpr_len,   path, path_len),   # Invalid index
            (psbt, i, 0x01,  pk,   pk_len,   mkl,   mkl_len,   fpr, fpr_len,   path, path_len),   # Invalid flags
            (psbt, i, flags, pk,   pk_len+1, mkl,   mkl_len,   fpr, fpr_len,   path, path_len),   # Bad pubkey length
            (psbt, i, flags, pk,   pk_len,   mkl,   mkl_len-1, fpr, fpr_len,   path, path_len),   # Bad tapleaf_hashes_len
            (psbt, i, flags, pk,   pk_len,   None,  mkl_len,   fpr, fpr_len,   path, path_len),   # Merkle length should be 0
            (psbt, i, flags, None, pk_len,   mkl,   mkl_len,   fpr, fpr_len,   path, path_len),   # No pubkey given
            (psbt, i, flags, pk,   pk_len,   mkl,   mkl_len,   fpr, fpr_len-1, path, path_len),   # Bad fpr length
            (psbt, i, flags, pk,   pk_len,   mkl,   mkl_len,   fpr, fpr_len,   None, path_len),   # NULL child path
            (psbt, i, flags, pk,   pk_len,   mkl,   mkl_len,   fpr, fpr_len,   path, path_len-1), # Bad child path length
        ]

        for args in invalid_args:
            self.assertEqual(WALLY_EINVAL, wally_psbt_add_input_taproot_keypath(*args))
            self.assertEqual(WALLY_EINVAL, wally_psbt_add_output_taproot_keypath(*args))

        valid_args = (psbt, i, flags, pk, pk_len, mkl, mkl_len, fpr, fpr_len, path, path_len)
        self.assertEqual(WALLY_OK, wally_psbt_add_input_taproot_keypath(*valid_args))
        self.assertEqual(WALLY_OK, wally_psbt_add_output_taproot_keypath(*valid_args))

    def test_redundant(self):
        """Test serializing redundant finalized input information"""
        buf, buf_len = make_cbuffer('00' * 4096)
        b64 = 'cHNidP8BAKACAAAAAqsJSaCMWvfEm4IS9Bfi8Vqz9cM9zxU4IagTn4d6W3vkAAAAAAD+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAEHakcwRAIgR1lmF5fAGwNrJZKJSGhiGDR9iYZLcZ4ff89X0eURZYcCIFMJ6r9Wqk2Ikf/REf3xM286KdqGbX+EhtdVRs7tr5MZASEDXNxh/HupccC1AaZGoqg7ECy0OIEhfKaC3Ibi1z+ogpIAAQEgAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4cBBBYAFIXRNTfy4mVAWjTbr6nj3aAfuCMIAAAA'
        psbt = self.parse_base64(b64)
        # Set a fake redeem script to the finalized input 0
        redeem, redeem_len = make_cbuffer('00' * 64)
        ret = wally_psbt_input_set_redeem_script(psbt.contents.inputs[0], redeem, redeem_len)
        self.assertEqual(ret, WALLY_OK)
        # This round trips by default, i.e. it doesn't include the redeem
        # script since the input is finalized
        serialized = self.to_base64(psbt)
        self.assertEqual(serialized, b64)
        # When SERIALIZE_FLAG_REDUNDANT is given, the redeem script is included
        SERIALIZE_FLAG_REDUNDANT = 0x1
        serialized = self.to_base64(psbt, None, SERIALIZE_FLAG_REDUNDANT)
        self.assertNotEqual(serialized, b64)

    def test_parse_malloc_fail(self):
        """Test that allocation failures when parsing return WALLY_ENOMEM"""
        _, is_elements_build = wally_is_elements_build()
        psbt = pointer(wally_psbt())

        for case in JSON['valid']:
            if case.get('is_pset', False) and not is_elements_build:
                continue # No Elements support, skip this test case
            ret = malloc_fail_loop(lambda: wally_psbt_from_base64(case['psbt'], 0, psbt))
            self.assertEqual(ret, WALLY_OK) # Parsed without failing
            wally_psbt_free(psbt)

if __name__ == '__main__':
    unittest.main()
