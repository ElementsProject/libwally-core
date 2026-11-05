import hashlib
import json
import unittest
from util import *

FLAG_GRIND_R = 0x4
MOD_NONE = 0
NETWORK_LIQUID = 0x03
SIGHASH_DEFAULT = 0x00
SIGTYPE_SW_V1 = 0x3
EC_FLAG_SCHNORR = 0x2
INIT_PSET = 1
BIP32_VER_MAIN_PRIVATE = 0x0488ADE4
BIP32_FLAG_KEY_PUBLIC = 0x1
BIP32_FP_LEN = 4

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

    def _ec_pubkey(self, seed_byte):
        """Return a valid compressed pubkey derived from a repeated seed byte"""
        priv, priv_len = make_cbuffer(seed_byte * 32)
        pub, pub_len = make_cbuffer('00' * 33)
        self.assertEqual(WALLY_OK,
            wally_ec_public_key_from_private_key(priv, priv_len, pub, pub_len))
        return pub, pub_len

    def test_musig2_participant_pubkeys(self):
        """Test MuSig2 participant pubkeys for PSBT inputs and outputs"""
        psbt = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt))

        tx_in = pointer(wally_tx_input())
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_input_at(psbt, 0, 0, tx_in))

        tx_output = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK, wally_tx_output_init_alloc(1234, b'\x59\x59', 2, tx_output))
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_output_at(psbt, 0, 0, tx_output))

        # Set a non-zero txhash on the input so v2 PSBT serialization succeeds
        txhash, txhash_len = make_cbuffer('ab' * 32)
        self.assertEqual(WALLY_OK, wally_psbt_set_input_previous_txid(psbt, 0, txhash, txhash_len))

        inp = psbt.contents.inputs[0]
        out = psbt.contents.outputs[0]

        # Valid keys: 33-byte agg_pubkey, 66-byte participants (2 x 33).
        # All keys must be valid curve points
        agg, agg_len = self._ec_pubkey('11')
        pk_a, _ = self._ec_pubkey('22')
        pk_b, _ = self._ec_pubkey('33')
        parts = bytes(pk_a) + bytes(pk_b)
        parts_len = len(parts)

        # Non-curve-point keys must be rejected
        bad_key, bad_key_len = make_cbuffer('02' + 'cd' * 32)
        self.assertEqual(WALLY_EINVAL,
            wally_psbt_input_add_musig2_participant_pubkeys(inp, bad_key, bad_key_len,
                                                            parts, parts_len))
        self.assertEqual(WALLY_EINVAL,
            wally_psbt_input_add_musig2_participant_pubkeys(inp, agg, agg_len,
                                                            bytes(bad_key) * 2, 66))

        # --- Invalid argument tests for input ---
        invalid_input_args = [
            (None, agg,  agg_len,   parts, parts_len),  # NULL input
            (inp,  None, agg_len,   parts, parts_len),  # NULL agg_pubkey
            (inp,  agg,  32,        parts, parts_len),  # agg_pubkey_len != 33
            (inp,  agg,  34,        parts, parts_len),  # agg_pubkey_len != 33
            (inp,  agg,  agg_len,   None,  parts_len),  # NULL participants
            (inp,  agg,  agg_len,   parts, 33),         # participants_len < 66 (one key only)
            (inp,  agg,  agg_len,   parts, 0),          # participants_len == 0
            (inp,  agg,  agg_len,   parts, 67),         # participants_len not multiple of 33
        ]
        for args in invalid_input_args:
            self.assertEqual(WALLY_EINVAL, wally_psbt_input_add_musig2_participant_pubkeys(*args))

        # --- Invalid argument tests for output ---
        invalid_output_args = [
            (None, agg,  agg_len,   parts, parts_len),  # NULL output
            (out,  None, agg_len,   parts, parts_len),  # NULL agg_pubkey
            (out,  agg,  32,        parts, parts_len),  # agg_pubkey_len != 33
            (out,  agg,  34,        parts, parts_len),  # agg_pubkey_len != 33
            (out,  agg,  agg_len,   None,  parts_len),  # NULL participants
            (out,  agg,  agg_len,   parts, 33),         # participants_len < 66
            (out,  agg,  agg_len,   parts, 0),          # participants_len == 0
            (out,  agg,  agg_len,   parts, 67),         # participants_len not multiple of 33
        ]
        for args in invalid_output_args:
            self.assertEqual(WALLY_EINVAL, wally_psbt_output_add_musig2_participant_pubkeys(*args))

        # --- Valid add: input ---
        self.assertEqual(WALLY_OK,
            wally_psbt_input_add_musig2_participant_pubkeys(inp, agg, agg_len, parts, parts_len))

        # find returns 1-based index
        ret, idx = wally_psbt_input_find_musig2_pubkey(inp, agg, agg_len)
        self.assertEqual((ret, idx), (WALLY_OK, 1))

        # Verify stored value matches participants via map access (66 bytes = 2 * 33)
        buf, buf_len = make_cbuffer('00' * 132)  # 132 hex chars = 66 bytes
        ret, written = wally_map_get_item(byref(inp.musig2_pubkeys), 0, buf, buf_len)
        self.assertEqual((ret, written), (WALLY_OK, parts_len))
        self.assertEqual(bytes(buf[:written]), bytes(parts[:parts_len]))

        # --- Valid add: output ---
        self.assertEqual(WALLY_OK,
            wally_psbt_output_add_musig2_participant_pubkeys(out, agg, agg_len, parts, parts_len))

        ret, idx = wally_psbt_output_find_musig2_pubkey(out, agg, agg_len)
        self.assertEqual((ret, idx), (WALLY_OK, 1))

        buf2, buf2_len = make_cbuffer('00' * 132)  # 132 hex chars = 66 bytes
        ret, written = wally_map_get_item(byref(out.musig2_pubkeys), 0, buf2, buf2_len)
        self.assertEqual((ret, written), (WALLY_OK, parts_len))
        self.assertEqual(bytes(buf2[:written]), bytes(parts[:parts_len]))

        # --- Round-trip: serialize and deserialize, verify participants survive ---
        b64_out = self.to_base64(psbt)
        wally_psbt_free(psbt)
        psbt2 = self.parse_base64(b64_out)
        # Re-serialize and compare (checks stable encoding)
        self.assertEqual(self.to_base64(psbt2), b64_out)

        inp2 = psbt2.contents.inputs[0]
        out2 = psbt2.contents.outputs[0]

        # Verify participants are present in deserialized PSBT
        ret, idx = wally_psbt_input_find_musig2_pubkey(inp2, agg, agg_len)
        self.assertEqual((ret, idx), (WALLY_OK, 1))

        ret, idx = wally_psbt_output_find_musig2_pubkey(out2, agg, agg_len)
        self.assertEqual((ret, idx), (WALLY_OK, 1))

        wally_psbt_free(psbt2)

    def _make_musig2_v2_psbt(self):
        """Helper: create a minimal v2 PSBT with 1 input and 1 output."""
        psbt = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt))
        tx_in = pointer(wally_tx_input())
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_input_at(psbt, 0, 0, tx_in))
        tx_output = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK, wally_tx_output_init_alloc(1234, b'\x59\x59', 2, tx_output))
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_output_at(psbt, 0, 0, tx_output))
        txhash, txhash_len = make_cbuffer('ab' * 32)
        self.assertEqual(WALLY_OK, wally_psbt_set_input_previous_txid(psbt, 0, txhash, txhash_len))
        return psbt

    def test_musig2_pubnonces_and_partial_sigs(self):
        """Test MuSig2 pubnonce and partial_sig PSBT fields (BIP-373)"""
        psbt = self._make_musig2_v2_psbt()
        inp = psbt.contents.inputs[0]

        participant, part_len = self._ec_pubkey('44')             # 33-byte compressed pubkey
        agg, agg_len = self._ec_pubkey('55')                      # 33-byte compressed pubkey
        leaf, leaf_len = make_cbuffer('ee' * 32)                  # 32-byte leaf hash
        nonce, nonce_len = make_cbuffer('ff' * 66)                # 66-byte pubnonce
        psig, psig_len = make_cbuffer('aa' * 32)                  # 32-byte partial sig

        # --- Invalid arg tests for add_musig2_pubnonce ---
        invalid_pubnonce_args = [
            (None, participant, part_len, agg, agg_len, None, 0, nonce, nonce_len),   # NULL input
            (inp, None, part_len, agg, agg_len, None, 0, nonce, nonce_len),           # NULL participant
            (inp, participant, 32, agg, agg_len, None, 0, nonce, nonce_len),          # wrong part_len
            (inp, participant, 34, agg, agg_len, None, 0, nonce, nonce_len),          # wrong part_len
            (inp, participant, part_len, None, agg_len, None, 0, nonce, nonce_len),   # NULL agg
            (inp, participant, part_len, agg, 32, None, 0, nonce, nonce_len),         # wrong agg_len
            (inp, participant, part_len, agg, agg_len, leaf, 31, nonce, nonce_len),   # bad leaf_len
            (inp, participant, part_len, agg, agg_len, leaf, 33, nonce, nonce_len),   # bad leaf_len
            (inp, participant, part_len, agg, agg_len, None, 32, nonce, nonce_len),   # NULL leaf + non-zero len
            (inp, participant, part_len, agg, agg_len, None, 0, None, nonce_len),     # NULL nonce
            (inp, participant, part_len, agg, agg_len, None, 0, nonce, 65),           # wrong nonce_len
            (inp, participant, part_len, agg, agg_len, None, 0, nonce, 67),           # wrong nonce_len
        ]
        for args in invalid_pubnonce_args:
            self.assertEqual(WALLY_EINVAL,
                             wally_psbt_input_add_musig2_pubnonce(*args))

        # --- Valid add without leaf hash ---
        self.assertEqual(WALLY_OK,
            wally_psbt_input_add_musig2_pubnonce(
                inp, participant, part_len, agg, agg_len, None, 0, nonce, nonce_len))

        ret, idx = wally_psbt_input_find_musig2_pubnonce(
            inp, participant, part_len, agg, agg_len, None, 0)
        self.assertEqual((ret, idx), (WALLY_OK, 1))

        # --- Valid add with leaf hash ---
        nonce2, nonce2_len = make_cbuffer('11' * 66)
        self.assertEqual(WALLY_OK,
            wally_psbt_input_add_musig2_pubnonce(
                inp, participant, part_len, agg, agg_len, leaf, leaf_len, nonce2, nonce2_len))

        ret, idx2 = wally_psbt_input_find_musig2_pubnonce(
            inp, participant, part_len, agg, agg_len, leaf, leaf_len)
        self.assertEqual((ret, idx2), (WALLY_OK, 2))

        # --- Count ---
        ret, count = wally_psbt_input_get_musig2_pubnonce_size(inp)
        self.assertEqual((ret, count), (WALLY_OK, 2))

        # --- Verify stored value via map access ---
        buf, buf_len = make_cbuffer('00' * 66)
        ret, written = wally_map_get_item(byref(inp.musig2_pubnonces), 0, buf, buf_len)
        self.assertEqual((ret, written), (WALLY_OK, nonce_len))
        self.assertEqual(bytes(buf[:written]), bytes(nonce[:nonce_len]))

        # --- Invalid arg tests for add_musig2_partial_sig ---
        invalid_psig_args = [
            (None, participant, part_len, agg, agg_len, None, 0, psig, psig_len),    # NULL input
            (inp, None, part_len, agg, agg_len, None, 0, psig, psig_len),            # NULL participant
            (inp, participant, 32, agg, agg_len, None, 0, psig, psig_len),           # wrong part_len
            (inp, participant, part_len, None, agg_len, None, 0, psig, psig_len),    # NULL agg
            (inp, participant, part_len, agg, 32, None, 0, psig, psig_len),          # wrong agg_len
            (inp, participant, part_len, agg, agg_len, leaf, 31, psig, psig_len),    # bad leaf_len
            (inp, participant, part_len, agg, agg_len, None, 32, psig, psig_len),    # NULL leaf + non-zero len
            (inp, participant, part_len, agg, agg_len, None, 0, None, psig_len),     # NULL psig
            (inp, participant, part_len, agg, agg_len, None, 0, psig, 31),           # wrong psig_len
            (inp, participant, part_len, agg, agg_len, None, 0, psig, 33),           # wrong psig_len
        ]
        for args in invalid_psig_args:
            self.assertEqual(WALLY_EINVAL,
                             wally_psbt_input_add_musig2_partial_sig(*args))

        # --- Valid add partial sig without leaf hash ---
        self.assertEqual(WALLY_OK,
            wally_psbt_input_add_musig2_partial_sig(
                inp, participant, part_len, agg, agg_len, None, 0, psig, psig_len))

        ret, idx = wally_psbt_input_find_musig2_partial_sig(
            inp, participant, part_len, agg, agg_len, None, 0)
        self.assertEqual((ret, idx), (WALLY_OK, 1))

        # --- Valid add partial sig with leaf hash ---
        psig2, psig2_len = make_cbuffer('bb' * 32)
        self.assertEqual(WALLY_OK,
            wally_psbt_input_add_musig2_partial_sig(
                inp, participant, part_len, agg, agg_len, leaf, leaf_len, psig2, psig2_len))

        ret, idx2 = wally_psbt_input_find_musig2_partial_sig(
            inp, participant, part_len, agg, agg_len, leaf, leaf_len)
        self.assertEqual((ret, idx2), (WALLY_OK, 2))

        ret, count = wally_psbt_input_get_musig2_partial_sig_size(inp)
        self.assertEqual((ret, count), (WALLY_OK, 2))

        # Verify stored value
        buf3, buf3_len = make_cbuffer('00' * 32)
        ret, written = wally_map_get_item(byref(inp.musig2_partial_sigs), 0, buf3, buf3_len)
        self.assertEqual((ret, written), (WALLY_OK, psig_len))
        self.assertEqual(bytes(buf3[:written]), bytes(psig[:psig_len]))

        # --- Round-trip: serialize and deserialize ---
        b64_out = self.to_base64(psbt)
        wally_psbt_free(psbt)
        psbt2 = self.parse_base64(b64_out)
        self.assertEqual(self.to_base64(psbt2), b64_out)

        inp2 = psbt2.contents.inputs[0]

        ret, count = wally_psbt_input_get_musig2_pubnonce_size(inp2)
        self.assertEqual((ret, count), (WALLY_OK, 2))

        ret, count = wally_psbt_input_get_musig2_partial_sig_size(inp2)
        self.assertEqual((ret, count), (WALLY_OK, 2))

        ret, idx = wally_psbt_input_find_musig2_pubnonce(
            inp2, participant, part_len, agg, agg_len, None, 0)
        self.assertEqual((ret, idx), (WALLY_OK, 1))

        ret, idx = wally_psbt_input_find_musig2_partial_sig(
            inp2, participant, part_len, agg, agg_len, leaf, leaf_len)
        self.assertEqual((ret, idx), (WALLY_OK, 2))

        wally_psbt_free(psbt2)

    def test_musig2_finalization_cleanup(self):
        """Test that finalization clears all MuSig2 fields (BIP-174)"""
        WALLY_PSBT_FINALIZE_NO_CLEAR = 0x1

        participant, part_len = self._ec_pubkey('44')
        agg, agg_len = self._ec_pubkey('55')
        pk_b, _ = self._ec_pubkey('66')
        parts = bytes(participant) + bytes(pk_b)
        parts_len = len(parts)
        nonce, nonce_len = make_cbuffer('ff' * 66)
        psig, psig_len = make_cbuffer('aa' * 32)
        dummy_script, dummy_script_len = make_cbuffer('51')  # OP_1 (trivially "spendable" for test)

        def setup_psbt_with_musig2():
            psbt = self._make_musig2_v2_psbt()
            inp = psbt.contents.inputs[0]
            # Mark input as already finalized so finalize_input goes to done: block
            self.assertEqual(WALLY_OK,
                wally_psbt_input_set_final_scriptsig(inp, dummy_script, dummy_script_len))
            # Add MuSig2 session fields
            self.assertEqual(WALLY_OK,
                wally_psbt_input_add_musig2_pubnonce(
                    inp, participant, part_len, agg, agg_len, None, 0, nonce, nonce_len))
            self.assertEqual(WALLY_OK,
                wally_psbt_input_add_musig2_partial_sig(
                    inp, participant, part_len, agg, agg_len, None, 0, psig, psig_len))
            # Add participant pubkeys
            self.assertEqual(WALLY_OK,
                wally_psbt_input_add_musig2_participant_pubkeys(inp, agg, agg_len, parts, parts_len))
            return psbt

        # --- Test with flags=0: all MuSig2 fields must be cleared ---
        psbt = setup_psbt_with_musig2()
        self.assertEqual(WALLY_OK, wally_psbt_finalize_input(psbt, 0, 0))

        inp = psbt.contents.inputs[0]
        ret, count = wally_psbt_input_get_musig2_pubnonce_size(inp)
        self.assertEqual((ret, count), (WALLY_OK, 0))  # cleared

        ret, count = wally_psbt_input_get_musig2_partial_sig_size(inp)
        self.assertEqual((ret, count), (WALLY_OK, 0))  # cleared

        ret, idx = wally_psbt_input_find_musig2_pubkey(inp, agg, agg_len)
        self.assertEqual((ret, idx), (WALLY_OK, 0))  # cleared

        # Values added after clearing are still validated
        bad, bad_len = make_cbuffer('02' + 'cd' * 32) # Not a valid point
        ret = wally_psbt_input_add_musig2_pubnonce(
            inp, bad, bad_len, agg, agg_len, None, 0, nonce, nonce_len)
        self.assertEqual(ret, WALLY_EINVAL)

        wally_psbt_free(psbt)

        # --- Test with WALLY_PSBT_FINALIZE_NO_CLEAR: all fields must remain ---
        psbt = setup_psbt_with_musig2()
        self.assertEqual(WALLY_OK, wally_psbt_finalize_input(psbt, 0, WALLY_PSBT_FINALIZE_NO_CLEAR))

        inp = psbt.contents.inputs[0]
        ret, count = wally_psbt_input_get_musig2_pubnonce_size(inp)
        self.assertEqual((ret, count), (WALLY_OK, 1))  # preserved

        ret, count = wally_psbt_input_get_musig2_partial_sig_size(inp)
        self.assertEqual((ret, count), (WALLY_OK, 1))  # preserved

        ret, idx = wally_psbt_input_find_musig2_pubkey(inp, agg, agg_len)
        self.assertEqual((ret, idx), (WALLY_OK, 1))  # preserved

        wally_psbt_free(psbt)

    def test_musig2_combine_sigs(self):
        """Test that psbt_combine with COMBINE_SIGS flag merges MuSig2 pubnonces and partial sigs"""
        WALLY_PSBT_COMBINE_SIGS = 0x1

        participant, part_len = self._ec_pubkey('44')
        agg, agg_len = self._ec_pubkey('55')
        nonce, nonce_len = make_cbuffer('ff' * 66)
        psig, psig_len = make_cbuffer('aa' * 32)

        # Build destination PSBT (base)
        dst = self._make_musig2_v2_psbt()

        # Build source (signature-only) PSBT with same input txhash/index
        src = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 1, 1, 0, 0, src))
        tx_in = pointer(wally_tx_input())
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_input_at(src, 0, 0, tx_in))
        txhash, txhash_len = make_cbuffer('ab' * 32)
        self.assertEqual(WALLY_OK, wally_psbt_set_input_previous_txid(src, 0, txhash, txhash_len))
        # No outputs: this is a signature-only PSBT (version 2, no outputs)

        src_inp = src.contents.inputs[0]
        self.assertEqual(WALLY_OK,
            wally_psbt_input_add_musig2_pubnonce(
                src_inp, participant, part_len, agg, agg_len, None, 0, nonce, nonce_len))
        self.assertEqual(WALLY_OK,
            wally_psbt_input_add_musig2_partial_sig(
                src_inp, participant, part_len, agg, agg_len, None, 0, psig, psig_len))

        # A signature-only serialization keeps the MuSig2 data to combine
        FLAG_SIGS_ONLY = 0x2 # WALLY_PSBT_SERIALIZE_SIGS_ONLY
        FLAG_LOOSE = 0x2 # WALLY_PSBT_PARSE_FLAG_LOOSE
        sigs_only = self.parse_base64(self.to_base64(src, flags=FLAG_SIGS_ONLY),
                                      flags=FLAG_LOOSE)
        wally_psbt_free(src)
        src = sigs_only

        # Combine with COMBINE_SIGS flag
        self.assertEqual(WALLY_OK, wally_psbt_combine_ex(dst, WALLY_PSBT_COMBINE_SIGS, src))

        # Verify MuSig2 fields were merged into dst
        dst_inp = dst.contents.inputs[0]

        ret, count = wally_psbt_input_get_musig2_pubnonce_size(dst_inp)
        self.assertEqual((ret, count), (WALLY_OK, 1))

        ret, idx = wally_psbt_input_find_musig2_pubnonce(
            dst_inp, participant, part_len, agg, agg_len, None, 0)
        self.assertEqual((ret, idx), (WALLY_OK, 1))

        ret, count = wally_psbt_input_get_musig2_partial_sig_size(dst_inp)
        self.assertEqual((ret, count), (WALLY_OK, 1))

        ret, idx = wally_psbt_input_find_musig2_partial_sig(
            dst_inp, participant, part_len, agg, agg_len, None, 0)
        self.assertEqual((ret, idx), (WALLY_OK, 1))

        wally_psbt_free(dst)
        wally_psbt_free(src)

    def test_musig2_v0_v2_conversion(self):
        """Test that MuSig2 fields survive v2->v0->v2 PSBT conversion"""
        psbt = self._make_musig2_v2_psbt()
        inp = psbt.contents.inputs[0]
        out = psbt.contents.outputs[0]

        agg, agg_len = self._ec_pubkey('11')
        participant, part_len = self._ec_pubkey('22')
        pk_b, _ = self._ec_pubkey('33')
        parts = bytes(participant) + bytes(pk_b)
        parts_len = len(parts)
        nonce, nonce_len = make_cbuffer('ff' * 66)
        psig, psig_len = make_cbuffer('aa' * 32)

        self.assertEqual(WALLY_OK,
            wally_psbt_input_add_musig2_participant_pubkeys(inp, agg, agg_len, parts, parts_len))
        self.assertEqual(WALLY_OK,
            wally_psbt_output_add_musig2_participant_pubkeys(out, agg, agg_len, parts, parts_len))
        self.assertEqual(WALLY_OK,
            wally_psbt_input_add_musig2_pubnonce(
                inp, participant, part_len, agg, agg_len, None, 0, nonce, nonce_len))
        self.assertEqual(WALLY_OK,
            wally_psbt_input_add_musig2_partial_sig(
                inp, participant, part_len, agg, agg_len, None, 0, psig, psig_len))

        # Convert v2 -> v0
        self.assertEqual(WALLY_OK, wally_psbt_set_version(psbt, 0, 0))
        # Convert v0 -> v2
        self.assertEqual(WALLY_OK, wally_psbt_set_version(psbt, 0, 2))

        # All MuSig2 fields must still be present after round-trip
        inp2 = psbt.contents.inputs[0]
        out2 = psbt.contents.outputs[0]

        ret, idx = wally_psbt_input_find_musig2_pubkey(inp2, agg, agg_len)
        self.assertEqual((ret, idx), (WALLY_OK, 1))

        ret, idx = wally_psbt_output_find_musig2_pubkey(out2, agg, agg_len)
        self.assertEqual((ret, idx), (WALLY_OK, 1))

        ret, count = wally_psbt_input_get_musig2_pubnonce_size(inp2)
        self.assertEqual((ret, count), (WALLY_OK, 1))

        ret, count = wally_psbt_input_get_musig2_partial_sig_size(inp2)
        self.assertEqual((ret, count), (WALLY_OK, 1))

        # Serialize and verify stable encoding
        b64_out = self.to_base64(psbt)
        wally_psbt_free(psbt)
        psbt3 = self.parse_base64(b64_out)
        self.assertEqual(self.to_base64(psbt3), b64_out)
        wally_psbt_free(psbt3)


    def test_musig2_psbt_populate_from_descriptor(self):
        """Test wally_psbt_populate_musig2_from_descriptor"""
        xpub1 = 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
        xpub2 = 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH'
        fp1 = 'deadbeef'
        fp2 = 'cafebabe'
        NETWORK_NONE = 0x00

        d = c_void_p()
        desc_str = f'tr(musig([{fp1}/86h/0h/0h]{xpub1}/0/*,[{fp2}/86h/0h/0h]{xpub2}/0/*))'
        ret = wally_descriptor_parse(desc_str, None, NETWORK_NONE, 0, d)
        self.assertEqual(ret, WALLY_OK, f'descriptor parse failed: {desc_str}')

        # Derive the descriptor's P2TR scriptpubkey for child_num=0
        spk, spk_len = make_cbuffer('00' * 34)
        ret, spk_written = wally_descriptor_to_script(d, 0, 0, 0, 0, 0, 0, spk, spk_len)
        self.assertEqual((ret, spk_written), (WALLY_OK, 34))
        spk_bytes = bytes(spk[:34])
        other_spk = b'\x00\x14' + b'\xab' * 20

        # Build a v2 PSBT with two inputs and two outputs. Input/output 0
        # match the descriptor's scriptpubkey; input/output 1 do not.
        psbt = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 2, 2, 0, 0, psbt))
        for i in range(2):
            tx_in = pointer(wally_tx_input())
            self.assertEqual(WALLY_OK, wally_psbt_add_tx_input_at(psbt, i, 0, tx_in))
        for i, script in enumerate([spk_bytes, other_spk]):
            utxo = pointer(wally_tx_output())
            self.assertEqual(WALLY_OK,
                             wally_tx_output_init_alloc(200000, script, len(script), utxo))
            self.assertEqual(WALLY_OK, wally_psbt_set_input_witness_utxo(psbt, i, utxo))
            tx_output = pointer(wally_tx_output())
            self.assertEqual(WALLY_OK,
                             wally_tx_output_init_alloc(1000, script, len(script), tx_output))
            self.assertEqual(WALLY_OK, wally_psbt_add_tx_output_at(psbt, i, 0, tx_output))

        # Invalid args
        self.assertEqual(WALLY_EINVAL, wally_psbt_populate_musig2_from_descriptor(None, d, 0, 0, 0))
        self.assertEqual(WALLY_EINVAL, wally_psbt_populate_musig2_from_descriptor(psbt, None, 0, 0, 0))
        self.assertEqual(WALLY_EINVAL, wally_psbt_populate_musig2_from_descriptor(psbt, d, 0, 0, 1))

        # Valid: populate with child_num=0
        self.assertEqual(WALLY_OK, wally_psbt_populate_musig2_from_descriptor(psbt, d, 0, 0, 0))

        inp = psbt.contents.inputs[0]
        out = psbt.contents.outputs[0]

        # TAP_INTERNAL_KEY must be set (32 bytes x-only)
        ret, ik_len = wally_psbt_get_input_taproot_internal_key_len(psbt, 0)
        self.assertEqual((ret, ik_len), (WALLY_OK, 32))

        ik_buf, ik_buf_len = make_cbuffer('00' * 32)
        ret, ik_written = wally_psbt_get_input_taproot_internal_key(psbt, 0, ik_buf, ik_buf_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(ik_written, 32)

        # MUSIG2_PARTICIPANT_PUBKEYS: try both 02 and 03 prefix for agg_comp
        ik_hex = bytes(ik_buf[:32]).hex()
        agg_02, _ = make_cbuffer('02' + ik_hex)
        agg_03, _ = make_cbuffer('03' + ik_hex)
        ret2, idx2 = wally_psbt_input_find_musig2_pubkey(inp, agg_02, 33)
        ret3, idx3 = wally_psbt_input_find_musig2_pubkey(inp, agg_03, 33)
        self.assertTrue((ret2 == WALLY_OK and idx2 > 0) or (ret3 == WALLY_OK and idx3 > 0),
                        'MUSIG2_PARTICIPANT_PUBKEYS not found in input')

        # Output must also have MUSIG2_PARTICIPANT_PUBKEYS
        ret2, idx2 = wally_psbt_output_find_musig2_pubkey(out, agg_02, 33)
        ret3, idx3 = wally_psbt_output_find_musig2_pubkey(out, agg_03, 33)
        self.assertTrue((ret2 == WALLY_OK and idx2 > 0) or (ret3 == WALLY_OK and idx3 > 0),
                        'MUSIG2_PARTICIPANT_PUBKEYS not found in output')

        # TAP_BIP32_DERIVATION: 2 entries (one per participant)
        self.assertEqual(inp.taproot_leaf_paths.num_items, 2)

        # Input/output 1 do not match the descriptor: they must be untouched
        ret, ik_len = wally_psbt_get_input_taproot_internal_key_len(psbt, 1)
        self.assertEqual((ret, ik_len), (WALLY_OK, 0),
                         'non-matching input must not get TAP_INTERNAL_KEY')
        wally_psbt_free(psbt)

        # The same, checking the maps of a PSBT whose only input/output does
        # not match. Note that only index 0 is read from python, since the
        # size of wally_psbt_input varies with the elements ABI.
        psbt = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt))
        self.assertEqual(WALLY_OK,
                         wally_psbt_add_tx_input_at(psbt, 0, 0, pointer(wally_tx_input())))
        utxo = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK,
                         wally_tx_output_init_alloc(200000, other_spk, len(other_spk), utxo))
        self.assertEqual(WALLY_OK, wally_psbt_set_input_witness_utxo(psbt, 0, utxo))
        tx_output = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK,
                         wally_tx_output_init_alloc(1000, other_spk, len(other_spk), tx_output))
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_output_at(psbt, 0, 0, tx_output))
        self.assertEqual(WALLY_OK, wally_psbt_populate_musig2_from_descriptor(psbt, d, 0, 0, 0))
        self.assertEqual(psbt.contents.inputs[0].musig2_pubkeys.num_items, 0)
        self.assertEqual(psbt.contents.inputs[0].taproot_leaf_paths.num_items, 0)
        self.assertEqual(psbt.contents.outputs[0].musig2_pubkeys.num_items, 0)

        wally_descriptor_free(d)
        wally_psbt_free(psbt)

        # Aggregate-then-derive musig() is rejected: its aggregate key is not
        # the taproot internal key, and signing it needs unsupported BIP-328
        # tweaks. Populating would write an internal key we cannot sign for.
        for desc_str in [f'tr(musig({xpub1},{xpub2})/0/*)',
                         f'tr(musig({xpub1},{xpub2})/0)']:
            d3 = c_void_p()
            ret = wally_descriptor_parse(desc_str, None, NETWORK_NONE, 0, d3)
            self.assertEqual(ret, WALLY_OK, f'descriptor parse failed: {desc_str}')
            spk3, spk3_len = make_cbuffer('00' * 34)
            ret, w = wally_descriptor_to_script(d3, 0, 0, 0, 0, 0, 0, spk3, spk3_len)
            self.assertEqual((ret, w), (WALLY_OK, 34))
            psbt3 = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt3))
            self.assertEqual(WALLY_OK,
                             wally_psbt_add_tx_input_at(psbt3, 0, 0, pointer(wally_tx_input())))
            utxo3 = pointer(wally_tx_output())
            self.assertEqual(WALLY_OK,
                             wally_tx_output_init_alloc(200000, bytes(spk3[:34]), 34, utxo3))
            self.assertEqual(WALLY_OK, wally_psbt_set_input_witness_utxo(psbt3, 0, utxo3))
            self.assertEqual(WALLY_EINVAL,
                             wally_psbt_populate_musig2_from_descriptor(psbt3, d3, 0, 0, 0),
                             f'expected rejection for: {desc_str}')
            # Nothing was written to the input
            ret, ik_len = wally_psbt_get_input_taproot_internal_key_len(psbt3, 0)
            self.assertEqual((ret, ik_len), (WALLY_OK, 0))
            wally_descriptor_free(d3)
            wally_psbt_free(psbt3)

        # No musig descriptor: no fields added
        psbt2 = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt2))
        d2 = c_void_p()
        ret = wally_descriptor_parse(f'pk({xpub1})', None, NETWORK_NONE, 0, d2)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(WALLY_OK, wally_psbt_populate_musig2_from_descriptor(psbt2, d2, 0, 0, 0))
        inp2 = psbt2.contents.inputs[0]
        self.assertEqual(inp2.taproot_leaf_paths.num_items, 0)
        wally_descriptor_free(d2)
        wally_psbt_free(psbt2)

    def test_input_reserved_0x19_field(self):
        """Input field type 0x19 (unassigned) with key data must be preserved as unknown"""
        psbt = self._make_musig2_v2_psbt()
        inp = psbt.contents.inputs[0]

        # An unknown map key is the full serialized key: type byte plus key data
        key = bytes([0x19]) + b'\x01\x02\x03'
        val = b'\xaa\xbb\xcc\xdd'
        m = POINTER(wally_map)()
        self.assertEqual(WALLY_OK, wally_map_init_alloc(1, None, byref(m)))
        self.assertEqual(WALLY_OK, wally_map_add(m, key, len(key), val, len(val)))
        self.assertEqual(WALLY_OK, wally_psbt_input_set_unknowns(inp, m))
        wally_map_free(m)

        b64 = self.to_base64(psbt)
        wally_psbt_free(psbt)

        # Parsing must succeed, with the 0x19 field in the input's unknowns map
        psbt2 = self.parse_base64(b64)
        inp2 = psbt2.contents.inputs[0]
        ret, idx = wally_psbt_input_find_unknown(inp2, key, len(key))
        self.assertEqual((ret, idx), (WALLY_OK, 1))
        buf, buf_len = make_cbuffer('00' * len(val))
        ret, written = wally_map_get_item(byref(inp2.unknowns), idx - 1, buf, buf_len)
        self.assertEqual((ret, written), (WALLY_OK, len(val)))
        self.assertEqual(bytes(buf[:written]), val)

        # And it must round-trip byte-identically
        self.assertEqual(self.to_base64(psbt2), b64)
        wally_psbt_free(psbt2)

    def _master_and_xpub(self, seed_byte):
        seed, seed_len = make_cbuffer(seed_byte * 64)  # 32 bytes
        m = POINTER(ext_key)()
        self.assertEqual(WALLY_OK, bip32_key_from_seed_alloc(
            seed, seed_len, BIP32_VER_MAIN_PRIVATE, 0, m))
        fp, fp_len = make_cbuffer('00' * BIP32_FP_LEN)
        self.assertEqual(WALLY_OK, bip32_key_get_fingerprint(m, fp, fp_len))
        ret, xpub = bip32_key_to_base58(m, BIP32_FLAG_KEY_PUBLIC)
        self.assertEqual(ret, WALLY_OK)
        return m, bytes(fp[:BIP32_FP_LEN]).hex(), xpub

    def test_sign_taproot_script_path(self):
        """Regression test for taproot script-path signing (psbt_sign_script_path).

        Builds a tr() with an internal key A and a pk(B) script leaf, then signs
        the script path with B's master key. The produced BIP-340 signature is
        deterministic (NULL aux_rand), so we lock it as a fixed vector."""
        mA, _fpA, xpubA = self._master_and_xpub('aa')
        mB, fpB, xpubB = self._master_and_xpub('bb')

        d = c_void_p()
        desc_str = f'tr({xpubA},pk([{fpB}]{xpubB}))'
        self.assertEqual(WALLY_OK, wally_descriptor_parse(desc_str, None, MOD_NONE, 0, d))

        # Derive the tr() output scriptpubkey (the prevout being spent)
        ret, slen = wally_descriptor_to_script_get_maximum_length(d, 0, 0, 0, 0, 0, 0)
        self.assertEqual(ret, WALLY_OK)
        spk, spk_len = make_cbuffer('00' * slen)
        ret, written = wally_descriptor_to_script(d, 0, 0, 0, 0, 0, 0, spk, spk_len)
        self.assertEqual(ret, WALLY_OK)

        # v2 PSBT with one taproot input and one output
        psbt = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt))
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_input_at(psbt, 0, 0, pointer(wally_tx_input())))
        tx_out = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK, wally_tx_output_init_alloc(1000, b'\x00\x14' + b'\xab'*20, 22, tx_out))
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_output_at(psbt, 0, 0, tx_out))

        # Witness utxo = the tr() prevout
        utxo = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK, wally_tx_output_init_alloc(100000, spk, written, utxo))
        self.assertEqual(WALLY_OK, wally_psbt_set_input_witness_utxo(psbt, 0, utxo))

        # Populate taproot fields (internal key, leaf scripts, tap bip32 derivation)
        self.assertEqual(WALLY_OK,
            wally_psbt_input_populate_taproot_from_descriptor(psbt, 0, d, 0, 0, 0))
        inp = psbt.contents.inputs[0]
        self.assertEqual(inp.taproot_leaf_scripts.num_items, 1)

        # Sign the script path with master B
        self.assertEqual(WALLY_OK, wally_psbt_sign_bip32(psbt, mB, 0))

        # Exactly one 64-byte (SIGHASH_DEFAULT) script-path signature, with the
        # expected deterministic value
        self.assertEqual(inp.taproot_leaf_signatures.num_items, 1)
        it = inp.taproot_leaf_signatures.items[0]
        self.assertEqual(it.value_len, 64)
        sig = bytes((c_ubyte * it.value_len).from_address(it.value)).hex()
        expected = '25a5ee769c23e8241661cab4c0050332f14a7f06250ad97a823bf67d0bde2a8f' \
                   '915195a83f96ec895df39eee11295b01154a024eb02496d85abe846534c41593'
        self.assertEqual(sig, expected)

        wally_descriptor_free(d)
        wally_psbt_free(psbt)
        bip32_key_free(mA)
        bip32_key_free(mB)

    def _descriptor_psbt(self, desc_str, network=MOD_NONE, is_pset=False,
                         multi_index=0, child_num=0):
        """Return a v2 PSBT whose input spends the descriptor's output"""
        d = c_void_p()
        self.assertEqual(WALLY_OK, wally_descriptor_parse(desc_str, None, network, 0, d))
        ret, slen = wally_descriptor_to_script_get_maximum_length(d, 0, 0, 0, multi_index,
                                                                  child_num, 0)
        self.assertEqual(ret, WALLY_OK)
        spk, spk_len = make_cbuffer('00' * slen)
        ret, spk_len = wally_descriptor_to_script(d, 0, 0, 0, multi_index, child_num,
                                                  0, spk, spk_len)
        self.assertEqual(ret, WALLY_OK)

        psbt = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 1, 1, 0, 1 if is_pset else 0, psbt))
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_input_at(psbt, 0, 0, pointer(wally_tx_input())))
        txid, txid_len = make_cbuffer('ab' * 32)
        self.assertEqual(WALLY_OK, wally_psbt_set_input_previous_txid(psbt, 0, txid, txid_len))
        out_script = b'\x00\x14' + b'\xab' * 20
        tx_out, utxo = pointer(wally_tx_output()), pointer(wally_tx_output())
        if is_pset:
            asset = b'\x01' + b'\x22' * 32
            for amount, script, script_len, out in [(1000, out_script, len(out_script), tx_out),
                                                    (100000, spk, spk_len, utxo)]:
                value = b'\x01' + amount.to_bytes(8, 'big')
                ret = wally_tx_elements_output_init_alloc(script, script_len,
                                                          asset, len(asset), value, len(value),
                                                          None, 0, None, 0, None, 0, out)
                self.assertEqual(ret, WALLY_OK)
        else:
            ret = wally_tx_output_init_alloc(1000, out_script, len(out_script), tx_out)
            self.assertEqual(ret, WALLY_OK)
            ret = wally_tx_output_init_alloc(100000, spk, spk_len, utxo)
            self.assertEqual(ret, WALLY_OK)
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_output_at(psbt, 0, 0, tx_out))
        self.assertEqual(WALLY_OK, wally_psbt_set_input_witness_utxo(psbt, 0, utxo))
        return psbt, d

    def test_taproot_populate_keypaths(self):
        """TAP_BIP32_DERIVATION lists the internal key and every leaf of each key"""
        mA, fpA, xpubA = self._master_and_xpub('aa')
        mB, fpB, xpubB = self._master_and_xpub('bb')
        A, B = f'[{fpA}]{xpubA}', f'[{fpB}]{xpubB}'
        for desc_str, num_leaf_hashes in [
                (f'tr({A})', [0]),
                (f'tr({A},pk({B}))', [0, 1]),
                # B is in two leaves, under two descriptor key indices
                (f'tr({A},{{pk({B}),and_v(v:pk({B}),older(10))}})', [0, 2])]:
            psbt, d = self._descriptor_psbt(desc_str)
            for _ in range(2): # Populating again succeeds
                ret = wally_psbt_input_populate_taproot_from_descriptor(psbt, 0, d, 0, 0, 0)
                self.assertEqual(ret, WALLY_OK)
            inp = psbt.contents.inputs[0]
            m = inp.taproot_leaf_hashes
            lens = sorted([m.items[i].value_len // 32 for i in range(m.num_items)])
            self.assertEqual(lens, num_leaf_hashes)
            self.assertEqual(inp.taproot_leaf_paths.num_items, len(num_leaf_hashes))
            # B signs every leaf it is in
            self.assertEqual(WALLY_OK, wally_psbt_sign_bip32(psbt, mB, 0))
            self.assertEqual(inp.taproot_leaf_signatures.num_items, num_leaf_hashes[-1])
            # The internal key signs for the key path
            self.assertEqual(WALLY_OK, wally_psbt_sign_bip32(psbt, mA, 0))
            ret, sig_len = wally_psbt_get_input_taproot_signature_len(psbt, 0)
            self.assertEqual((ret, sig_len), (WALLY_OK, 64))
            wally_descriptor_free(d)
            wally_psbt_free(psbt)

        _, is_elements_build = wally_is_elements_build()
        if is_elements_build:
            # Bitcoin descriptors can't populate PSETs, and vice versa
            for desc_str, is_pset, network in [(f'tr({A},pk({B}))', True, MOD_NONE),
                                               (f'eltr({A},pk({B}))', False, NETWORK_LIQUID)]:
                psbt, d = self._descriptor_psbt(desc_str, network, not is_pset)
                wally_psbt_free(psbt)
                psbt, _ = self._descriptor_psbt(f'tr({A})', MOD_NONE, is_pset)
                ret = wally_psbt_input_populate_taproot_from_descriptor(psbt, 0, d, 0, 0, 0)
                self.assertEqual(ret, WALLY_EINVAL)
                ret = wally_psbt_output_populate_taproot_from_descriptor(psbt, 0, d, 0, 0, 0)
                self.assertEqual(ret, WALLY_EINVAL)
                wally_descriptor_free(d)
                wally_psbt_free(psbt)
        bip32_key_free(mA)
        bip32_key_free(mB)

    def _keypaths(self, m):
        """Return a dict of map key: (fingerprint, path) for a keypath map"""
        ret = {}
        for i in range(m.num_items):
            item = m.items[i]
            key = bytes((c_ubyte * item.key_len).from_address(item.key))
            val = bytes((c_ubyte * item.value_len).from_address(item.value))
            path = [int.from_bytes(val[j:j + 4], 'little') for j in range(4, len(val), 4)]
            ret[key] = (val[:4].hex(), path)
        return ret

    def _derive_pubkey(self, master, path):
        """Return the compressed pubkey of master derived along path"""
        derived = POINTER(ext_key)()
        c_path = (c_uint32 * len(path))(*path)
        ret = bip32_key_from_parent_path_alloc(master, c_path, len(path),
                                               BIP32_FLAG_KEY_PUBLIC, derived)
        self.assertEqual(ret, WALLY_OK)
        pub = bytes(derived.contents.pub_key)
        bip32_key_free(derived)
        return pub

    def test_taproot_populate_multipath(self):
        """Multi-path keys are populated for the given multi-path index"""
        mA, fpA, xpubA = self._master_and_xpub('aa')
        mB, fpB, xpubB = self._master_and_xpub('bb')
        # B is not multi-path, so ignores the multi-path index
        desc_str = f'tr([{fpA}]{xpubA}/<0;1>/*,pk([{fpB}]{xpubB}/7/*))'
        for multi_index in (0, 1):
            psbt, d = self._descriptor_psbt(desc_str, multi_index=multi_index, child_num=3)
            ret = wally_psbt_input_populate_taproot_from_descriptor(psbt, 0, d,
                                                                    multi_index, 3, 0)
            self.assertEqual(ret, WALLY_OK)
            keypaths = self._keypaths(psbt.contents.inputs[0].taproot_leaf_paths)
            self.assertEqual(sorted(keypaths.values()),
                             sorted([(fpA, [multi_index, 3]), (fpB, [7, 3])]))
            # Both keys sign: A for the key path, B for the script path
            self.assertEqual(WALLY_OK, wally_psbt_sign_bip32(psbt, mB, 0))
            self.assertEqual(psbt.contents.inputs[0].taproot_leaf_signatures.num_items, 1)
            self.assertEqual(WALLY_OK, wally_psbt_sign_bip32(psbt, mA, 0))
            ret, sig_len = wally_psbt_get_input_taproot_signature_len(psbt, 0)
            self.assertEqual((ret, sig_len), (WALLY_OK, 64))
            wally_descriptor_free(d)
            wally_psbt_free(psbt)
        bip32_key_free(mA)
        bip32_key_free(mB)

    def test_musig2_populate_participants(self):
        """musig() participants of each key type are populated"""
        m1, fp1, xpub1 = self._master_and_xpub('11')
        priv, priv_len = make_cbuffer('22' * 32)
        ret, wif = wally_wif_from_bytes(priv, priv_len, 0x80, 0) # Compressed
        self.assertEqual(ret, WALLY_OK)
        wif_pub, wif_pub_len = make_cbuffer('00' * 33)
        ret = wally_ec_public_key_from_private_key(priv, priv_len, wif_pub, wif_pub_len)
        self.assertEqual(ret, WALLY_OK)
        hex_pub = '03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659'
        desc_str = f'tr(musig([{fp1}]{xpub1}/<0;1>/*,{wif},{hex_pub}))'
        for multi_index in (0, 1):
            psbt, d = self._descriptor_psbt(desc_str, multi_index=multi_index, child_num=2)
            # Populating with the other multi-path index matches no input
            ret = wally_psbt_populate_musig2_from_descriptor(psbt, d, 1 - multi_index, 2, 0)
            self.assertEqual(ret, WALLY_OK)
            inp = psbt.contents.inputs[0]
            self.assertEqual(inp.musig2_pubkeys.num_items, 0)

            ret = wally_psbt_populate_musig2_from_descriptor(psbt, d, multi_index, 2, 0)
            self.assertEqual(ret, WALLY_OK)
            xpub_pub = self._derive_pubkey(m1, [multi_index, 2])
            participants = sorted([xpub_pub, bytes(wif_pub), bytes.fromhex(hex_pub)])
            item = inp.musig2_pubkeys.items[0]
            value = bytes((c_ubyte * item.value_len).from_address(item.value))
            self.assertEqual(value, b''.join(participants))
            self.assertEqual(self._keypaths(inp.taproot_leaf_paths), {
                xpub_pub[1:]: (fp1, [multi_index, 2]),
                bytes(wif_pub)[1:]: ('00000000', []),
                bytes.fromhex(hex_pub)[1:]: ('00000000', [])})
            wally_descriptor_free(d)
            wally_psbt_free(psbt)
        bip32_key_free(m1)

    def test_taproot_script_path_finalize(self):
        """Test finalizing taproot script path spends"""
        mA, fpA, xpubA = self._master_and_xpub('aa')
        mB, fpB, xpubB = self._master_and_xpub('bb')
        B = f'[{fpB}]{xpubB}'
        for leaf, num_items in [('pk', 3), ('pkh', 4)]:
            psbt, d = self._descriptor_psbt(f'tr({xpubA},{leaf}({B}))')
            ret = wally_psbt_input_populate_taproot_from_descriptor(psbt, 0, d, 0, 0, 0)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(WALLY_OK, wally_psbt_sign_bip32(psbt, mB, 0))
            self.assertEqual(WALLY_OK, wally_psbt_finalize(psbt, 0))
            ret, is_finalized = wally_psbt_is_finalized(psbt)
            self.assertEqual((ret, is_finalized), (WALLY_OK, 1))
            witness = psbt.contents.inputs[0].final_witness.contents
            self.assertEqual(witness.num_items, num_items)
            # Values added after finalizing are still validated
            inp = psbt.contents.inputs[0]
            bad, bad_len = make_cbuffer('00' * 64)
            sig, sig_len = make_cbuffer('11' * 300)
            ret = wally_psbt_input_add_taproot_leaf_signature(inp, bad, bad_len, sig, sig_len)
            self.assertEqual(ret, WALLY_EINVAL)
            wally_descriptor_free(d)
            wally_psbt_free(psbt)

        # Only tapscript leaves are signed and satisfied
        psbt, d = self._descriptor_psbt(f'tr({xpubA},pk({B}))')
        ret = wally_psbt_input_populate_taproot_from_descriptor(psbt, 0, d, 0, 0, 0)
        self.assertEqual(ret, WALLY_OK)
        item = psbt.contents.inputs[0].taproot_leaf_scripts.items[0]
        ctrl = (c_ubyte * item.key_len).from_address(item.key)
        ctrl[0] = (ctrl[0] & 1) | 0xc2 # Non-tapscript leaf version
        self.assertEqual(WALLY_OK, wally_psbt_sign_bip32(psbt, mB, 0))
        self.assertEqual(psbt.contents.inputs[0].taproot_leaf_signatures.num_items, 0)
        wally_descriptor_free(d)
        wally_psbt_free(psbt)
        bip32_key_free(mA)
        bip32_key_free(mB)

    def test_taproot_empty_leaf_script(self):
        """Empty taproot leaf scripts are valid, but are not signed"""
        mA, fpA, xpubA = self._master_and_xpub('aa')
        mB, fpB, xpubB = self._master_and_xpub('bb')
        psbt, d = self._descriptor_psbt(f'tr({xpubA},pk([{fpB}]{xpubB}))')
        ret = wally_psbt_input_populate_taproot_from_descriptor(psbt, 0, d, 0, 0, 0)
        self.assertEqual(ret, WALLY_OK)
        inp = psbt.contents.inputs[0]

        # Add an empty leaf script, and list its hash in B's derivation
        item = inp.taproot_leaf_scripts.items[0]
        ctrl = bytes((c_ubyte * item.key_len).from_address(item.key)) + b'\x11' * 32
        ret = wally_psbt_input_add_taproot_leaf_script(inp, ctrl, len(ctrl), None, 0)
        self.assertEqual(ret, WALLY_OK)
        tag = hashlib.sha256(b'TapLeaf').digest()
        empty_leaf_hash = hashlib.sha256(tag + tag + bytes([ctrl[0] & 0xfe, 0])).digest()
        m = inp.taproot_leaf_hashes
        item = [m.items[i] for i in range(m.num_items) if m.items[i].value_len][0] # B
        key = bytes((c_ubyte * item.key_len).from_address(item.key))
        value = bytes((c_ubyte * item.value_len).from_address(item.value)) + empty_leaf_hash
        ret = wally_map_replace(byref(inp.taproot_leaf_hashes), key, len(key), value, len(value))
        self.assertEqual(ret, WALLY_OK)

        # The empty leaf round-trips, with an empty TAP_TREE leaf in the output
        out = psbt.contents.outputs[0]
        tree = bytes([0, 0xc0, 0]) # depth, leaf version, empty script
        ret = wally_map_add_integer(byref(out.taproot_tree), 1, tree, len(tree))
        self.assertEqual(ret, WALLY_OK)
        b64 = self.to_base64(psbt)
        psbt2 = self.parse_base64(b64)
        self.assertEqual(self.to_base64(psbt2), b64)
        self.assertEqual(psbt2.contents.inputs[0].taproot_leaf_scripts.num_items, 2)
        wally_psbt_free(psbt2)

        # B only signs the leaf with its key
        self.assertEqual(WALLY_OK, wally_psbt_sign_bip32(psbt, mB, 0))
        self.assertEqual(inp.taproot_leaf_signatures.num_items, 1)
        wally_descriptor_free(d)
        wally_psbt_free(psbt)
        bip32_key_free(mA)
        bip32_key_free(mB)

    def test_taproot_leaf_key_not_keypath_signed(self):
        """A key that only appears in a leaf is never key-path signed, even
        when the leaf script it belongs to is not present in the input."""
        mA, fpA, xpubA = self._master_and_xpub('aa')
        mB, fpB, xpubB = self._master_and_xpub('bb')
        psbt, d = self._descriptor_psbt(f'tr([{fpA}]{xpubA},pk([{fpB}]{xpubB}))')
        ret = wally_psbt_input_populate_taproot_from_descriptor(psbt, 0, d, 0, 0, 0)
        self.assertEqual(ret, WALLY_OK)
        inp = psbt.contents.inputs[0]
        # B participates only in the leaf; its derivation lists the leaf hash
        self.assertEqual(inp.taproot_leaf_scripts.num_items, 1)
        # Drop the leaf script, as if the PSBT carried B's leaf derivation but
        # not the leaf script itself. B can no longer be script-path signed and
        # must not be key-path signed (that would store an invalid TAP_KEY_SIG).
        inp.taproot_leaf_scripts.num_items = 0
        self.assertEqual(WALLY_OK, wally_psbt_sign_bip32(psbt, mB, 0))
        self.assertEqual(inp.taproot_leaf_signatures.num_items, 0)
        ret, sig_len = wally_psbt_get_input_taproot_signature_len(psbt, 0)
        self.assertEqual((ret, sig_len), (WALLY_OK, 0)) # No key-path signature
        # An unrelated key C listed with no leaf hashes is not the internal
        # key (TAP_INTERNAL_KEY is A), so it must not be key-path signed either
        mC, fpC, _ = self._master_and_xpub('cc')
        kC = POINTER(ext_key)()
        self.assertEqual(WALLY_OK, bip32_key_from_parent_alloc(mC, 0, BIP32_FLAG_KEY_PUBLIC, kC))
        xonlyC = bytes(kC.contents.pub_key[1:33])
        fpr, path = bytes.fromhex(fpC), (c_uint32 * 1)(0)
        self.assertEqual(WALLY_OK, wally_psbt_add_input_taproot_keypath(
            psbt, 0, 0, xonlyC, 32, None, 0, fpr, 4, path, 1))
        self.assertEqual(WALLY_OK, wally_psbt_sign_bip32(psbt, mC, 0))
        self.assertEqual(inp.taproot_leaf_signatures.num_items, 0)
        ret, sig_len = wally_psbt_get_input_taproot_signature_len(psbt, 0)
        self.assertEqual((ret, sig_len), (WALLY_OK, 0)) # No key-path signature
        bip32_key_free(kC)
        bip32_key_free(mC)
        # The internal key (no leaf hashes) is still key-path signed
        self.assertEqual(WALLY_OK, wally_psbt_sign_bip32(psbt, mA, 0))
        ret, sig_len = wally_psbt_get_input_taproot_signature_len(psbt, 0)
        self.assertEqual((ret, sig_len), (WALLY_OK, 64))
        wally_descriptor_free(d)
        wally_psbt_free(psbt)
        bip32_key_free(mA)
        bip32_key_free(mB)

    def test_taproot_populate_malloc_fail(self):
        """Allocation failures while populating are returned"""
        mA, fpA, xpubA = self._master_and_xpub('aa')
        mB, fpB, xpubB = self._master_and_xpub('bb')
        A, B = f'[{fpA}]{xpubA}', f'[{fpB}]{xpubB}'
        psbt, d = self._descriptor_psbt(f'tr({A},{{pk({B}),and_v(v:pk({B}),older(10))}})')
        def populate():
            return wally_psbt_input_populate_taproot_from_descriptor(psbt, 0, d, 0, 0, 0)
        ret = malloc_fail_loop(populate, allowed_rets=[WALLY_ENOMEM, WALLY_OK])
        self.assertEqual(ret, WALLY_OK)
        inp = psbt.contents.inputs[0]
        self.assertEqual(inp.taproot_leaf_scripts.num_items, 2)
        self.assertEqual(inp.taproot_leaf_paths.num_items, 2)
        m = inp.taproot_leaf_hashes
        lens = sorted([m.items[i].value_len // 32 for i in range(m.num_items)])
        self.assertEqual(lens, [0, 2])
        wally_descriptor_free(d)
        wally_psbt_free(psbt)
        bip32_key_free(mA)
        bip32_key_free(mB)

    def test_taproot_internal_key_in_leaf(self):
        """An internal key that also appears in a leaf is signed for both the
        key path and its leaves."""
        mA, fpA, xpubA = self._master_and_xpub('aa')
        mB, fpB, xpubB = self._master_and_xpub('bb')
        A, B = f'[{fpA}]{xpubA}', f'[{fpB}]{xpubB}'
        psbt, d = self._descriptor_psbt(f'tr({A},{{pk({A}),pk({B})}})')
        ret = wally_psbt_input_populate_taproot_from_descriptor(psbt, 0, d, 0, 0, 0)
        self.assertEqual(ret, WALLY_OK)
        inp = psbt.contents.inputs[0]
        # A is listed once, with the hash of the leaf it appears in
        self.assertEqual(inp.taproot_leaf_paths.num_items, 2)
        m = inp.taproot_leaf_hashes
        lens = sorted([m.items[i].value_len // 32 for i in range(m.num_items)])
        self.assertEqual(lens, [1, 1])
        # B signs only its leaf
        self.assertEqual(WALLY_OK, wally_psbt_sign_bip32(psbt, mB, 0))
        self.assertEqual(inp.taproot_leaf_signatures.num_items, 1)
        ret, sig_len = wally_psbt_get_input_taproot_signature_len(psbt, 0)
        self.assertEqual((ret, sig_len), (WALLY_OK, 0))
        # A signs its leaf and the key path (once a key-path signature is
        # present the input is spendable, so no further keys are signed)
        self.assertEqual(WALLY_OK, wally_psbt_sign_bip32(psbt, mA, 0))
        self.assertEqual(inp.taproot_leaf_signatures.num_items, 2)
        ret, sig_len = wally_psbt_get_input_taproot_signature_len(psbt, 0)
        self.assertEqual((ret, sig_len), (WALLY_OK, 64))
        # The key-path signature finalizes the input
        self.assertEqual(WALLY_OK, wally_psbt_finalize_input(psbt, 0, 0))
        self.assertEqual(inp.final_witness.contents.num_items, 1)
        wally_descriptor_free(d)
        wally_psbt_free(psbt)
        bip32_key_free(mA)
        bip32_key_free(mB)

    def test_finalize_bare_multisig(self):
        """A bare (non-P2SH) multisig scriptSig is OP_0 <sig>... with no
        trailing script push (the multisig script is the scriptPubKey)."""
        pubs = []
        for i in (111, 222):
            pub, pub_len = make_cbuffer('00' * 33)
            self.assertEqual(WALLY_OK, wally_ec_public_key_from_private_key(
                i.to_bytes(32, 'big'), 32, pub, pub_len))
            pubs.append(bytes(pub))
        desc = 'multi(2,%s,%s)' % (pubs[0].hex(), pubs[1].hex())
        d = c_void_p()
        self.assertEqual(WALLY_OK, wally_descriptor_parse(desc, None, 0, 0, d))
        spk, spk_len = make_cbuffer('00' * 300)
        ret, spk_len = wally_descriptor_to_script(d, 0, 0, 0, 0, 0, 0, spk, spk_len)
        self.assertEqual(ret, WALLY_OK)
        spk_bytes = bytes(spk[:spk_len])
        wally_descriptor_free(d)

        # Previous tx with a bare multisig output, spent by a v0 PSBT
        ptx = pointer(wally_tx())
        self.assertEqual(WALLY_OK, wally_tx_init_alloc(2, 0, 1, 1, ptx))
        txid, txid_len = make_cbuffer('ab' * 32)
        self.assertEqual(WALLY_OK, wally_tx_add_raw_input(ptx, txid, txid_len, 0,
                                                          0xffffffff, None, 0, None, 0))
        o = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK, wally_tx_output_init_alloc(100000, spk, spk_len, o))
        self.assertEqual(WALLY_OK, wally_tx_add_output(ptx, o))
        stx = pointer(wally_tx())
        self.assertEqual(WALLY_OK, wally_tx_init_alloc(2, 0, 1, 1, stx))
        tid, tid_len = make_cbuffer('00' * 32)
        self.assertEqual(WALLY_OK, wally_tx_get_txid(ptx, tid, tid_len))
        self.assertEqual(WALLY_OK, wally_tx_add_raw_input(stx, tid, tid_len, 0,
                                                          0xffffffff, None, 0, None, 0))
        o2 = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK, wally_tx_output_init_alloc(90000, spk, spk_len, o2))
        self.assertEqual(WALLY_OK, wally_tx_add_output(stx, o2))
        psbt = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(0, 0, 0, 0, 0, psbt))
        self.assertEqual(WALLY_OK, wally_psbt_set_global_tx(psbt, stx))
        self.assertEqual(WALLY_OK, wally_psbt_set_input_utxo(psbt, 0, ptx))

        # Inject partial signatures (finalization assembles, does not verify)
        der = bytes.fromhex('3044' + '0220' + '11' * 32 + '0220' + '22' * 32) + b'\x01'
        for pub in pubs:
            self.assertEqual(WALLY_OK, wally_psbt_add_input_signature(
                psbt, 0, pub, len(pub), der, len(der)))

        self.assertEqual(WALLY_OK, wally_psbt_finalize(psbt, 0))
        ret, ss_len = wally_psbt_get_input_final_scriptsig_len(psbt, 0)
        self.assertEqual(ret, WALLY_OK)
        buf, buf_len = make_cbuffer('00' * ss_len)
        ret, written = wally_psbt_get_input_final_scriptsig(psbt, 0, buf, buf_len)
        script_sig = bytes(buf[:written])
        # OP_0 followed by the two pushed signatures, and nothing else
        self.assertEqual(script_sig, bytes([0]) + bytes([len(der)]) + der + bytes([len(der)]) + der)
        self.assertFalse(script_sig.endswith(spk_bytes))
        wally_psbt_free(psbt)

    def _timelock_psbt(self, miniscript, version, locktime, sequence):
        """A v0 PSBT spending wsh(miniscript) with a dummy signature injected,
        and the given spending tx version/locktime and input sequence."""
        der = bytes.fromhex('3044' + '0220' + '11' * 32 + '0220' + '22' * 32) + b'\x01'
        pub, pub_len = make_cbuffer('00' * 33)
        self.assertEqual(WALLY_OK, wally_ec_public_key_from_private_key(
            (111).to_bytes(32, 'big'), 32, pub, pub_len))
        pub = bytes(pub)
        ms = miniscript % pub.hex()
        d = c_void_p()
        self.assertEqual(WALLY_OK, wally_descriptor_parse(ms, None, 0, 2, d))
        ws, ws_len = make_cbuffer('00' * 256)
        ret, ws_len = wally_descriptor_to_script(d, 0, 0, 0, 0, 0, 0, ws, ws_len)
        self.assertEqual(ret, WALLY_OK)
        wscript = bytes(ws[:ws_len])
        wally_descriptor_free(d)
        spk = b'\x00\x20' + hashlib.sha256(wscript).digest()

        stx = pointer(wally_tx())
        self.assertEqual(WALLY_OK, wally_tx_init_alloc(version, locktime, 1, 1, stx))
        tid, tid_len = make_cbuffer('00' * 32)
        self.assertEqual(WALLY_OK, wally_tx_add_raw_input(stx, tid, tid_len, 0,
                                                          sequence, None, 0, None, 0))
        ob, ob_len = make_cbuffer(spk.hex())
        o = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK, wally_tx_output_init_alloc(100000, ob, ob_len, o))
        self.assertEqual(WALLY_OK, wally_tx_add_output(stx, o))
        psbt = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(0, 0, 0, 0, 0, psbt))
        self.assertEqual(WALLY_OK, wally_psbt_set_global_tx(psbt, stx))
        u = pointer(wally_tx_output())
        ob2, ob2_len = make_cbuffer(spk.hex())
        self.assertEqual(WALLY_OK, wally_tx_output_init_alloc(100000, ob2, ob2_len, u))
        self.assertEqual(WALLY_OK, wally_psbt_set_input_witness_utxo(psbt, 0, u))
        wsb, wsb_len = make_cbuffer(wscript.hex())
        self.assertEqual(WALLY_OK, wally_psbt_set_input_witness_script(psbt, 0, wsb, wsb_len))
        self.assertEqual(WALLY_OK, wally_psbt_add_input_signature(psbt, 0, pub, len(pub),
                                                                  der, len(der)))
        return psbt

    def test_finalize_timelock_branches(self):
        """older()/after() branches are only finalized when the spending tx's
        version, locktime and input sequence actually satisfy the lock."""
        FINAL, NON_FINAL = 0xffffffff, 0xfffffffe
        def finalized(ms, version, locktime, sequence):
            psbt = self._timelock_psbt(ms, version, locktime, sequence)
            wally_psbt_finalize(psbt, 0)
            ret, is_finalized = wally_psbt_is_finalized(psbt)
            self.assertEqual(ret, WALLY_OK)
            wally_psbt_free(psbt)
            return is_finalized == 1

        older = 'and_v(v:pk(%s),older(144))'
        # CSV (BIP-112) is only enforced for tx version >= 2
        self.assertTrue(finalized(older, 2, 0, 144))
        self.assertFalse(finalized(older, 1, 0, 144))
        # The input's relative locktime (sequence) must satisfy older(144)
        self.assertFalse(finalized(older, 2, 0, 10))
        # Sequence bits outside the BIP-68 type flag/value are ignored...
        self.assertTrue(finalized(older, 2, 0, (1 << 16) | 144))
        # ...except the disable flag, which disables relative locks entirely
        self.assertFalse(finalized(older, 2, 0, (1 << 31) | 144))

        # Time-based older() (BIP-68 type flag set) is satisfied by a
        # time-based sequence whose value reaches the lock
        TIME = 1 << 22
        t_older = f'and_v(v:pk(%s),older({TIME | 10}))'
        self.assertTrue(finalized(t_older, 2, 0, TIME | 10))
        self.assertTrue(finalized(t_older, 2, 0, TIME | 11))
        self.assertFalse(finalized(t_older, 2, 0, TIME | 9))
        self.assertFalse(finalized(t_older, 1, 0, TIME | 10))
        self.assertFalse(finalized(t_older, 2, 0, (1 << 31) | TIME | 10))
        # The lock and sequence must both be height-based or both time-based
        self.assertFalse(finalized(t_older, 2, 0, 10))
        self.assertFalse(finalized(older, 2, 0, TIME | 144))

        after = 'and_v(v:pk(%s),after(500000))'
        # The spending tx locktime must reach after(500000)...
        self.assertTrue(finalized(after, 2, 500000, NON_FINAL))
        self.assertFalse(finalized(after, 2, 499999, NON_FINAL))
        # ...and CLTV (BIP-65) is only enforced for a non-final input sequence
        self.assertFalse(finalized(after, 2, 500000, FINAL))

    def test_finalize_malloc_fail(self):
        """Allocation failures while finalizing are returned"""
        mA, fpA, xpubA = self._master_and_xpub('aa')
        mB, fpB, xpubB = self._master_and_xpub('bb')
        _, _, xpubK = self._master_and_xpub('cc')
        A, B = f'[{fpA}]{xpubA}', f'[{fpB}]{xpubB}'

        def get_witness(psbt):
            witness = psbt.contents.inputs[0].final_witness
            if not witness:
                return None # Not finalized
            return [string_at(witness.contents.items[i].witness, witness.contents.items[i].len)
                    for i in range(witness.contents.num_items)]

        for leaf in [f'or_d(pk({A}),pk({B}))', f'multi_a(1,{A},{B})']:
            psbt, d = self._descriptor_psbt(f'tr({xpubK},{leaf})')
            ret = wally_psbt_input_populate_taproot_from_descriptor(psbt, 0, d, 0, 0, 0)
            self.assertEqual(ret, WALLY_OK)
            for m in (mA, mB):
                self.assertEqual(WALLY_OK, wally_psbt_sign_bip32(psbt, m, 0))
            b64 = self.to_base64(psbt)
            self.assertEqual(WALLY_OK, wally_psbt_finalize_input(psbt, 0, 0))
            expected = get_witness(psbt) # The lightest witness, using A's sig
            wally_psbt_free(psbt)

            def finalize():
                nonlocal psbt
                with no_malloc_failures():
                    psbt = self.parse_base64(b64)
                ret = wally_psbt_finalize_input(psbt, 0, 0)
                if ret == WALLY_OK:
                    # Failures may only succeed if they don't change the
                    # result, e.g. by choosing a different satisfaction
                    self.assertEqual(get_witness(psbt), expected)
                wally_psbt_free(psbt)
                return ret
            ret = malloc_fail_loop(finalize, allowed_rets=[WALLY_ENOMEM, WALLY_OK])
            self.assertEqual(ret, WALLY_OK)
            wally_descriptor_free(d)
        bip32_key_free(mA)
        bip32_key_free(mB)

    def test_finalize_preimage_length(self):
        """Miniscript hash fragments are only satisfied by 32 byte preimages"""
        for preimage, expected in [(bytes(range(32)), 1), (b'\x01', 0), (b'\x01' * 33, 0)]:
            h = hashlib.sha256(preimage).digest()
            # SIZE 32 EQUALVERIFY SHA256 <h> EQUAL
            ws = bytes([0x82, 0x01, 0x20, 0x88, 0xa8, 0x20]) + h + bytes([0x87])
            psbt, d = self._descriptor_psbt(f'raw(0020{hashlib.sha256(ws).hexdigest()})')
            wally_descriptor_free(d)
            inp = psbt.contents.inputs[0]
            self.assertEqual(WALLY_OK, wally_psbt_input_set_witness_script(inp, ws, len(ws)))
            ret = wally_map_preimage_sha256_add(byref(inp.preimages), preimage, len(preimage))
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(WALLY_OK, wally_psbt_finalize_input(psbt, 0, 0))
            ret, is_finalized = wally_psbt_is_finalized(psbt)
            self.assertEqual((ret, is_finalized), (WALLY_OK, expected))
            wally_psbt_free(psbt)

    def test_sign_taproot_script_path_elements(self):
        """Test taproot script path signing of PSETs"""
        _, is_elements_build = wally_is_elements_build()
        if not is_elements_build:
            self.skipTest('Elements support is disabled')
        mA, fpA, xpubA = self._master_and_xpub('aa')
        mB, fpB, xpubB = self._master_and_xpub('bb')
        psbt, d = self._descriptor_psbt(f'eltr({xpubA},pk([{fpB}]{xpubB}))',
                                        NETWORK_LIQUID, True)
        genesis, genesis_len = make_cbuffer('11' * 32)
        ret = wally_psbt_set_global_genesis_blockhash(psbt, genesis, genesis_len)
        self.assertEqual(ret, WALLY_OK)
        ret = wally_psbt_input_populate_taproot_from_descriptor(psbt, 0, d, 0, 0, 0)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(WALLY_OK, wally_psbt_sign_bip32(psbt, mB, 0))
        inp = psbt.contents.inputs[0]
        self.assertEqual(inp.taproot_leaf_signatures.num_items, 1)
        self.assertEqual(WALLY_OK, wally_psbt_finalize(psbt, 0))
        witness = inp.final_witness.contents
        self.assertEqual(witness.num_items, 3)
        sig = string_at(witness.items[0].witness, witness.items[0].len)
        script = string_at(witness.items[1].witness, witness.items[1].len)
        ctrl = string_at(witness.items[2].witness, witness.items[2].len)
        self.assertEqual(ctrl[0] & 0xfe, 0xc4) # Elements tapscript leaf version

        # The signature verifies against the Elements script path sighash
        tx = pointer(wally_tx())
        self.assertEqual(WALLY_OK, wally_psbt_extract(psbt, 0, tx))
        utxo = inp.witness_utxo.contents
        scripts, values, assets = [pointer(wally_map()) for _ in range(3)]
        for m, v, l in [(scripts, utxo.script, utxo.script_len),
                        (values, utxo.value, utxo.value_len),
                        (assets, utxo.asset, utxo.asset_len)]:
            self.assertEqual(WALLY_OK, wally_map_init(1, None, m))
            self.assertEqual(WALLY_OK, wally_map_add_integer(m, 0, v, l))
        sighash, sighash_len = make_cbuffer('00' * 32)
        ret = wally_tx_get_input_signature_hash(tx, 0, scripts, assets, values,
                                                script, len(script), 0, 0xffffffff,
                                                None, 0, genesis, genesis_len,
                                                SIGHASH_DEFAULT, SIGTYPE_SW_V1,
                                                None, sighash, sighash_len)
        self.assertEqual(ret, WALLY_OK)
        xonly = script[1:33] # <xonly> CHECKSIG
        ret = wally_ec_sig_verify(xonly, len(xonly), sighash, sighash_len,
                                  EC_FLAG_SCHNORR, sig, len(sig))
        self.assertEqual(ret, WALLY_OK)
        for m in (scripts, values, assets):
            wally_map_clear(m)
        wally_tx_free(tx)
        wally_descriptor_free(d)
        wally_psbt_free(psbt)
        bip32_key_free(mA)
        bip32_key_free(mB)


class Csv2of2SmokeTests(unittest.TestCase):
    """Regression smoke: CSV2OF2_1 and CSV2OF2_1_OPT PSBT finalization witnesses."""

    _SK_1 = bytes([1] + [0] * 31)  # user key
    _SK_2 = bytes([2] + [0] * 31)  # recovery key
    _CSV_BLOCKS = 17               # minimum

    @classmethod
    def setUpClass(cls):
        pk_buf, pk_len = make_cbuffer('00' * 33)
        assert wally_ec_public_key_from_private_key(cls._SK_1, 32, pk_buf, pk_len) == WALLY_OK
        cls._PK_1 = bytes(pk_buf)
        assert wally_ec_public_key_from_private_key(cls._SK_2, 32, pk_buf, pk_len) == WALLY_OK
        cls._PK_2 = bytes(pk_buf)

    def _build_psbt(self, is_optimized):
        two_pks = self._PK_1 + self._PK_2
        pks_buf, pks_len = make_cbuffer(two_pks.hex())

        csv_buf, csv_len = make_cbuffer('00' * 200)
        fn = (wally_scriptpubkey_csv_2of2_then_1_from_bytes_opt if is_optimized
              else wally_scriptpubkey_csv_2of2_then_1_from_bytes)
        ret, written = fn(pks_buf, pks_len, self._CSV_BLOCKS, 0, csv_buf, csv_len)
        self.assertEqual(ret, WALLY_OK)
        csv_script = bytes(csv_buf[:written])

        p2wsh_spk = bytes([0x00, 0x20]) + hashlib.sha256(csv_script).digest()
        spk_buf, spk_len = make_cbuffer(p2wsh_spk.hex())

        output = pointer(wally_tx_output())
        self.assertEqual(wally_tx_output_init_alloc(1_000_000, spk_buf, spk_len, output), WALLY_OK)

        tx = pointer(wally_tx())
        self.assertEqual(wally_tx_init_alloc(2, 0, 1, 1, tx), WALLY_OK)
        txid_buf, txid_len = make_cbuffer('ab' * 32)
        # sequence=0 ensures CSV is not expired (0 < CSV_BLOCKS=17)
        self.assertEqual(wally_tx_add_raw_input(tx, txid_buf, txid_len, 0, 0, None, 0, None, 0), WALLY_OK)
        self.assertEqual(wally_tx_add_output(tx, output), WALLY_OK)

        psbt = pointer(wally_psbt())
        self.assertEqual(wally_psbt_init_alloc(0, 0, 0, 0, 0, psbt), WALLY_OK)
        self.assertEqual(wally_psbt_set_global_tx(psbt, tx), WALLY_OK)
        self.assertEqual(wally_psbt_set_input_witness_utxo(psbt, 0, output), WALLY_OK)

        csv_cbuf, csv_cbuf_len = make_cbuffer(csv_script.hex())
        self.assertEqual(wally_psbt_set_input_witness_script(psbt, 0, csv_cbuf, csv_cbuf_len), WALLY_OK)

        fp, fp_len = make_cbuffer('00' * 4)
        for pk in [self._PK_1, self._PK_2]:
            pk_cbuf, pk_cbuf_len = make_cbuffer(pk.hex())
            self.assertEqual(wally_psbt_add_input_keypath(psbt, 0, pk_cbuf, pk_cbuf_len,
                                                          fp, fp_len, None, 0), WALLY_OK)
        return psbt, csv_script

    def _sign_and_get_witness(self, psbt):
        for sk in [self._SK_1, self._SK_2]:
            sk_buf, sk_len = make_cbuffer(sk.hex())
            wally_psbt_sign(psbt, sk_buf, sk_len, FLAG_GRIND_R)

        self.assertEqual(wally_psbt_finalize(psbt, 0), WALLY_OK)
        ret, is_finalized = wally_psbt_is_finalized(psbt)
        self.assertEqual((ret, is_finalized), (WALLY_OK, 1))

        fw = psbt.contents.inputs[0].final_witness
        self.assertIsNotNone(fw)
        stack = fw.contents
        items = []
        for i in range(stack.num_items):
            item = stack.items[i]
            if item.len == 0 or not item.witness:
                items.append(b'')
            else:
                items.append(string_at(item.witness, item.len))
        return items

    def test_csv2of2_1_two_key_spend(self):
        """CSV2OF2_1: two-key spend produces [sig_2, sig_1, csv_script]."""
        psbt, csv_script = self._build_psbt(is_optimized=False)
        witness = self._sign_and_get_witness(psbt)
        wally_psbt_free(psbt)
        self.assertEqual(len(witness), 3)
        self.assertGreater(len(witness[0]), 0)  # sig_2
        self.assertGreater(len(witness[1]), 0)  # sig_1
        self.assertEqual(witness[2], csv_script)

    def test_csv2of2_1_opt_two_key_spend(self):
        """CSV2OF2_1_OPT: two-key spend produces [sig_2, sig_1, csv_script]."""
        psbt, csv_script = self._build_psbt(is_optimized=True)
        witness = self._sign_and_get_witness(psbt)
        wally_psbt_free(psbt)
        self.assertEqual(len(witness), 3)
        self.assertGreater(len(witness[0]), 0)  # sig_2
        self.assertGreater(len(witness[1]), 0)  # sig_1
        self.assertEqual(witness[2], csv_script)


if __name__ == '__main__':
    unittest.main()
