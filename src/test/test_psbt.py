import hashlib
import json
import unittest
from util import *

FLAG_GRIND_R = 0x4
MOD_NONE = 0
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
        psbt = self.parse_base64(case['psbt'])
        wally_psbt_signing_cache_enable(psbt, 0) # Enable signing cache
        for wif in case['privkeys']:
            self.assertEqual(WALLY_OK, wally_wif_to_bytes(wif, 0xEF, 0, priv_key, priv_key_len))
            self.assertEqual(expected_ret, wally_psbt_sign(psbt, priv_key, priv_key_len, FLAG_GRIND_R))
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

    def test_psbt(self):
        """Test creating and modifying various PSBT fields"""
        tx = pointer(wally_tx())
        self.assertEqual(WALLY_OK, wally_tx_init_alloc(2, 0, 2, 2, tx))

        psbt = pointer(wally_psbt())
        for ver, result in [
            (0, 'cHNidP8A'),
            (1, None),
            (2, 'cHNidP8BAgQCAAAAAQQBAAEFAQAB+wQCAAAAAA=='),
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

        # Valid keys: 33-byte agg_pubkey, 66-byte participants (2 x 33)
        agg, agg_len = make_cbuffer('02' + 'ab' * 32)
        parts, parts_len = make_cbuffer('03' + 'cd' * 32 + '02' + 'ef' * 32)

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

        participant, part_len = make_cbuffer('02' + 'ab' * 32)   # 33-byte compressed pubkey
        agg, agg_len = make_cbuffer('03' + 'cd' * 32)            # 33-byte compressed pubkey
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
        ret, count = wally_psbt_input_get_musig2_pubnonce_count(inp)
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

        ret, count = wally_psbt_input_get_musig2_partial_sig_count(inp)
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

        ret, count = wally_psbt_input_get_musig2_pubnonce_count(inp2)
        self.assertEqual((ret, count), (WALLY_OK, 2))

        ret, count = wally_psbt_input_get_musig2_partial_sig_count(inp2)
        self.assertEqual((ret, count), (WALLY_OK, 2))

        ret, idx = wally_psbt_input_find_musig2_pubnonce(
            inp2, participant, part_len, agg, agg_len, None, 0)
        self.assertEqual((ret, idx), (WALLY_OK, 1))

        ret, idx = wally_psbt_input_find_musig2_partial_sig(
            inp2, participant, part_len, agg, agg_len, leaf, leaf_len)
        self.assertEqual((ret, idx), (WALLY_OK, 2))

        wally_psbt_free(psbt2)

    def test_musig2_finalization_cleanup(self):
        """Test that finalization clears MuSig2 session fields but preserves participant pubkeys"""
        WALLY_PSBT_FINALIZE_NO_CLEAR = 0x1

        participant, part_len = make_cbuffer('02' + 'ab' * 32)
        agg, agg_len = make_cbuffer('03' + 'cd' * 32)
        parts, parts_len = make_cbuffer('03' + 'cd' * 32 + '02' + 'ef' * 32)
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
            # Add participant pubkeys (metadata, should be preserved)
            self.assertEqual(WALLY_OK,
                wally_psbt_input_add_musig2_participant_pubkeys(inp, agg, agg_len, parts, parts_len))
            return psbt

        # --- Test with flags=0: session fields must be cleared, participant pubkeys preserved ---
        psbt = setup_psbt_with_musig2()
        self.assertEqual(WALLY_OK, wally_psbt_finalize_input(psbt, 0, 0))

        inp = psbt.contents.inputs[0]
        ret, count = wally_psbt_input_get_musig2_pubnonce_count(inp)
        self.assertEqual((ret, count), (WALLY_OK, 0))  # cleared

        ret, count = wally_psbt_input_get_musig2_partial_sig_count(inp)
        self.assertEqual((ret, count), (WALLY_OK, 0))  # cleared

        ret, idx = wally_psbt_input_find_musig2_pubkey(inp, agg, agg_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertGreater(idx, 0)  # preserved

        wally_psbt_free(psbt)

        # --- Test with WALLY_PSBT_FINALIZE_NO_CLEAR: all fields must remain ---
        psbt = setup_psbt_with_musig2()
        self.assertEqual(WALLY_OK, wally_psbt_finalize_input(psbt, 0, WALLY_PSBT_FINALIZE_NO_CLEAR))

        inp = psbt.contents.inputs[0]
        ret, count = wally_psbt_input_get_musig2_pubnonce_count(inp)
        self.assertEqual((ret, count), (WALLY_OK, 1))  # preserved

        ret, count = wally_psbt_input_get_musig2_partial_sig_count(inp)
        self.assertEqual((ret, count), (WALLY_OK, 1))  # preserved

        ret, idx = wally_psbt_input_find_musig2_pubkey(inp, agg, agg_len)
        self.assertEqual((ret, idx), (WALLY_OK, 1))  # preserved

        wally_psbt_free(psbt)

    def test_musig2_combine_sigs(self):
        """Test that psbt_combine with COMBINE_SIGS flag merges MuSig2 pubnonces and partial sigs"""
        WALLY_PSBT_COMBINE_SIGS = 0x1

        participant, part_len = make_cbuffer('02' + 'ab' * 32)
        agg, agg_len = make_cbuffer('03' + 'cd' * 32)
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

        # Combine with COMBINE_SIGS flag
        self.assertEqual(WALLY_OK, wally_psbt_combine_ex(dst, WALLY_PSBT_COMBINE_SIGS, src))

        # Verify MuSig2 fields were merged into dst
        dst_inp = dst.contents.inputs[0]

        ret, count = wally_psbt_input_get_musig2_pubnonce_count(dst_inp)
        self.assertEqual((ret, count), (WALLY_OK, 1))

        ret, idx = wally_psbt_input_find_musig2_pubnonce(
            dst_inp, participant, part_len, agg, agg_len, None, 0)
        self.assertEqual((ret, idx), (WALLY_OK, 1))

        ret, count = wally_psbt_input_get_musig2_partial_sig_count(dst_inp)
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

        agg, agg_len = make_cbuffer('02' + 'ab' * 32)
        parts, parts_len = make_cbuffer('03' + 'cd' * 32 + '02' + 'ef' * 32)
        participant, part_len = make_cbuffer('02' + 'ab' * 32)
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

        ret, count = wally_psbt_input_get_musig2_pubnonce_count(inp2)
        self.assertEqual((ret, count), (WALLY_OK, 1))

        ret, count = wally_psbt_input_get_musig2_partial_sig_count(inp2)
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

        psbt = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt))
        # Add one input and one output to the v2 PSBT
        tx_in = pointer(wally_tx_input())
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_input_at(psbt, 0, 0, tx_in))
        tx_output = pointer(wally_tx_output())
        self.assertEqual(WALLY_OK, wally_tx_output_init_alloc(1000, b'\x00\x14' + b'\xab' * 20, 22, tx_output))
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_output_at(psbt, 0, 0, tx_output))

        d = c_void_p()
        desc_str = f'tr(musig([{fp1}/86h/0h/0h]{xpub1}/0/*,[{fp2}/86h/0h/0h]{xpub2}/0/*))'
        ret = wally_descriptor_parse(desc_str, None, NETWORK_NONE, 0, d)
        self.assertEqual(ret, WALLY_OK, f'descriptor parse failed: {desc_str}')

        # Invalid args
        self.assertEqual(WALLY_EINVAL, wally_psbt_populate_musig2_from_descriptor(None, d, 0, 0))
        self.assertEqual(WALLY_EINVAL, wally_psbt_populate_musig2_from_descriptor(psbt, None, 0, 0))
        self.assertEqual(WALLY_EINVAL, wally_psbt_populate_musig2_from_descriptor(psbt, d, 0, 1))

        # Valid: populate with child_num=0
        self.assertEqual(WALLY_OK, wally_psbt_populate_musig2_from_descriptor(psbt, d, 0, 0))

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

        wally_descriptor_free(d)
        wally_psbt_free(psbt)

        # No musig descriptor: no fields added
        psbt2 = pointer(wally_psbt())
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt2))
        d2 = c_void_p()
        ret = wally_descriptor_parse(f'pk({xpub1})', None, NETWORK_NONE, 0, d2)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(WALLY_OK, wally_psbt_populate_musig2_from_descriptor(psbt2, d2, 0, 0))
        inp2 = psbt2.contents.inputs[0]
        self.assertEqual(inp2.taproot_leaf_paths.num_items, 0)
        wally_descriptor_free(d2)
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
            wally_psbt_input_set_taproot_from_descriptor(psbt, 0, d, 0, 0, 0))
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
