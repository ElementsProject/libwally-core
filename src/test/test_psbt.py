import json
import unittest
from util import *

FLAG_GRIND_R = 0x4
MOD_NONE = 0
INIT_PSET = 1

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


    def test_segwit_input_with_only_non_witness_utxo(self):
        """A segwit v0 input backed only by a full previous tx must be signed
           with the segwit digest, exactly as the same input with a
           witness_utxo is. Covers p2wpkh, p2sh-p2wpkh, p2wsh and p2sh-p2wsh,
           and that a previous tx whose txid does not match is not signed from."""
        EC_FLAG_ECDSA, SIGHASH_ALL, TX_FLAG_USE_WITNESS, EXTRACT_NON_FINAL = 0x1, 0x1, 0x1, 0x1
        AMOUNT = 100000
        priv, priv_len = make_cbuffer('00' * 32)
        wif = 'KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d'
        self.assertEqual(wally_wif_to_bytes(wif, 0x80, 0, priv, priv_len), WALLY_OK)
        pub, pub_len = make_cbuffer('0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c')
        cases = [
            # (with witness_utxo, with non_witness_utxo only, scriptCode, expected signed result)
            ('cHNidP8BAHECAAAAAQ1uGqyWuXswoO+9JP28P/bNV3rmmdNMmCHmpQZOgnLlAAAAAAD9////AmDqAAAAAAAAFgAUERERERERERERERERERERERERERFYmAAAAAAAABYAFD40mF3Kb93J+zaZQOTH2OKHP1KcAAAAAAABAR+ghgEAAAAAABYAFMDOvNbD08qMddxexi6+VTMO+RDiIgYDMNVP0N1CCm5fjTYk9fNILK41D3nV8HU79b7vnC2RrzwYc8XaClQAAIAAAACAAAAAgAAAAAAAAAAAAAAA',
             'cHNidP8BAHECAAAAAQ1uGqyWuXswoO+9JP28P/bNV3rmmdNMmCHmpQZOgnLlAAAAAAD9////AmDqAAAAAAAAFgAUERERERERERERERERERERERERERFYmAAAAAAAABYAFD40mF3Kb93J+zaZQOTH2OKHP1KcAAAAAAABAFIBAAAAATMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AaCGAQAAAAAAFgAUwM681sPTyox13F7GLr5VMw75EOIAAAAAIgYDMNVP0N1CCm5fjTYk9fNILK41D3nV8HU79b7vnC2RrzwYc8XaClQAAIAAAACAAAAAgAAAAAAAAAAAAAAA',
             '76a914c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e288ac',
             'cHNidP8BAHECAAAAAQ1uGqyWuXswoO+9JP28P/bNV3rmmdNMmCHmpQZOgnLlAAAAAAD9////AmDqAAAAAAAAFgAUERERERERERERERERERERERERERFYmAAAAAAAABYAFD40mF3Kb93J+zaZQOTH2OKHP1KcAAAAAAABAFIBAAAAATMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AaCGAQAAAAAAFgAUwM681sPTyox13F7GLr5VMw75EOIAAAAAIgIDMNVP0N1CCm5fjTYk9fNILK41D3nV8HU79b7vnC2RrzxHMEQCIAGpnqnwveyaOmiomVdjJygrH3B0YNcLf22I2vxTfOe7AiAN1mGM/3HJUhRN2G8Li5iXXhXTikU6qo0JtXXKKGu4KwEiBgMw1U/Q3UIKbl+NNiT180gsrjUPedXwdTv1vu+cLZGvPBhzxdoKVAAAgAAAAIAAAACAAAAAAAAAAAAAAAA='),
            ('cHNidP8BAHECAAAAAboeLsLbBFh4AgNWzIpgpRE7Wufs/GHuHFCSVmmKvhwYAAAAAAD9////AmDqAAAAAAAAFgAUERERERERERERERERERERERERERFYmAAAAAAAABYAFD40mF3Kb93J+zaZQOTH2OKHP1KcAAAAAAABASCghgEAAAAAABepFKa1iI/dyPoZPdNT0Q5c1ajuqwZOhwEEFgAUwM681sPTyox13F7GLr5VMw75EOIiBgMw1U/Q3UIKbl+NNiT180gsrjUPedXwdTv1vu+cLZGvPBhzxdoKVAAAgAAAAIAAAACAAAAAAAAAAAAAAAA=',
             'cHNidP8BAHECAAAAAboeLsLbBFh4AgNWzIpgpRE7Wufs/GHuHFCSVmmKvhwYAAAAAAD9////AmDqAAAAAAAAFgAUERERERERERERERERERERERERERFYmAAAAAAAABYAFD40mF3Kb93J+zaZQOTH2OKHP1KcAAAAAAABAFMBAAAAATMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AaCGAQAAAAAAF6kUprWIj93I+hk901PRDlzVqO6rBk6HAAAAAAEEFgAUwM681sPTyox13F7GLr5VMw75EOIiBgMw1U/Q3UIKbl+NNiT180gsrjUPedXwdTv1vu+cLZGvPBhzxdoKVAAAgAAAAIAAAACAAAAAAAAAAAAAAAA=',
             '76a914c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e288ac',
             'cHNidP8BAHECAAAAAboeLsLbBFh4AgNWzIpgpRE7Wufs/GHuHFCSVmmKvhwYAAAAAAD9////AmDqAAAAAAAAFgAUERERERERERERERERERERERERERFYmAAAAAAAABYAFD40mF3Kb93J+zaZQOTH2OKHP1KcAAAAAAABAFMBAAAAATMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AaCGAQAAAAAAF6kUprWIj93I+hk901PRDlzVqO6rBk6HAAAAACICAzDVT9DdQgpuX402JPXzSCyuNQ951fB1O/W+75wtka88RzBEAiBooHFbPNLzW14aAl3SsB619rybBATMKQsUUoBbzzks9QIgJsegrPQnub5GpBJvOAMX6ALvdFzingU2+fJt2Ox1q0ABAQQWABTAzrzWw9PKjHXcXsYuvlUzDvkQ4iIGAzDVT9DdQgpuX402JPXzSCyuNQ951fB1O/W+75wtka88GHPF2gpUAACAAAAAgAAAAIAAAAAAAAAAAAAAAA=='),
            ('cHNidP8BAHECAAAAARIVfBEpHEX+10MUk9FbSz79Bq2TxXuonw7aKDFFfYmlAAAAAAD9////AmDqAAAAAAAAFgAUERERERERERERERERERERERERERFYmAAAAAAAABYAFD40mF3Kb93J+zaZQOTH2OKHP1KcAAAAAAABASughgEAAAAAACIAIFE35fzzPT9bLxRFZLyfU2A9bTAnZpCTyoNA3Yhwq8NtAQUlUSEDMNVP0N1CCm5fjTYk9fNILK41D3nV8HU79b7vnC2RrzxRriIGAzDVT9DdQgpuX402JPXzSCyuNQ951fB1O/W+75wtka88GHPF2gpUAACAAAAAgAAAAIAAAAAAAAAAAAAAAA==',
             'cHNidP8BAHECAAAAARIVfBEpHEX+10MUk9FbSz79Bq2TxXuonw7aKDFFfYmlAAAAAAD9////AmDqAAAAAAAAFgAUERERERERERERERERERERERERERFYmAAAAAAAABYAFD40mF3Kb93J+zaZQOTH2OKHP1KcAAAAAAABAF4BAAAAATMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AaCGAQAAAAAAIgAgUTfl/PM9P1svFEVkvJ9TYD1tMCdmkJPKg0DdiHCrw20AAAAAAQUlUSEDMNVP0N1CCm5fjTYk9fNILK41D3nV8HU79b7vnC2RrzxRriIGAzDVT9DdQgpuX402JPXzSCyuNQ951fB1O/W+75wtka88GHPF2gpUAACAAAAAgAAAAIAAAAAAAAAAAAAAAA==',
             '51210330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c51ae',
             'cHNidP8BAHECAAAAARIVfBEpHEX+10MUk9FbSz79Bq2TxXuonw7aKDFFfYmlAAAAAAD9////AmDqAAAAAAAAFgAUERERERERERERERERERERERERERFYmAAAAAAAABYAFD40mF3Kb93J+zaZQOTH2OKHP1KcAAAAAAABAF4BAAAAATMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AaCGAQAAAAAAIgAgUTfl/PM9P1svFEVkvJ9TYD1tMCdmkJPKg0DdiHCrw20AAAAAIgIDMNVP0N1CCm5fjTYk9fNILK41D3nV8HU79b7vnC2RrzxHMEQCIHXqw7l4C7H8cEabU6WSM5pSJrBfF5k+I/4TSe3uCfdvAiAJcXTFXiHjOc1cyCDz3uxQr0jfBenfR39W7Bj71tUA3gEBBSVRIQMw1U/Q3UIKbl+NNiT180gsrjUPedXwdTv1vu+cLZGvPFGuIgYDMNVP0N1CCm5fjTYk9fNILK41D3nV8HU79b7vnC2RrzwYc8XaClQAAIAAAACAAAAAgAAAAAAAAAAAAAAA'),
            ('cHNidP8BAHECAAAAAZz5uza8hRpRHCAyrJe/I5v5q/8Ejk01EAfACAeB+Wy3AAAAAAD9////AmDqAAAAAAAAFgAUERERERERERERERERERERERERERFYmAAAAAAAABYAFD40mF3Kb93J+zaZQOTH2OKHP1KcAAAAAAABASCghgEAAAAAABepFAV1G984QyN9C6OQHpSs5oC9fJYPhwEEIgAgUTfl/PM9P1svFEVkvJ9TYD1tMCdmkJPKg0DdiHCrw20BBSVRIQMw1U/Q3UIKbl+NNiT180gsrjUPedXwdTv1vu+cLZGvPFGuIgYDMNVP0N1CCm5fjTYk9fNILK41D3nV8HU79b7vnC2RrzwYc8XaClQAAIAAAACAAAAAgAAAAAAAAAAAAAAA',
             'cHNidP8BAHECAAAAAZz5uza8hRpRHCAyrJe/I5v5q/8Ejk01EAfACAeB+Wy3AAAAAAD9////AmDqAAAAAAAAFgAUERERERERERERERERERERERERERFYmAAAAAAAABYAFD40mF3Kb93J+zaZQOTH2OKHP1KcAAAAAAABAFMBAAAAATMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AaCGAQAAAAAAF6kUBXUb3zhDI30Lo5AelKzmgL18lg+HAAAAAAEEIgAgUTfl/PM9P1svFEVkvJ9TYD1tMCdmkJPKg0DdiHCrw20BBSVRIQMw1U/Q3UIKbl+NNiT180gsrjUPedXwdTv1vu+cLZGvPFGuIgYDMNVP0N1CCm5fjTYk9fNILK41D3nV8HU79b7vnC2RrzwYc8XaClQAAIAAAACAAAAAgAAAAAAAAAAAAAAA',
             '51210330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c51ae',
             'cHNidP8BAHECAAAAAZz5uza8hRpRHCAyrJe/I5v5q/8Ejk01EAfACAeB+Wy3AAAAAAD9////AmDqAAAAAAAAFgAUERERERERERERERERERERERERERFYmAAAAAAAABYAFD40mF3Kb93J+zaZQOTH2OKHP1KcAAAAAAABAFMBAAAAATMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AaCGAQAAAAAAF6kUBXUb3zhDI30Lo5AelKzmgL18lg+HAAAAACICAzDVT9DdQgpuX402JPXzSCyuNQ951fB1O/W+75wtka88RzBEAiBTyr4ZFdc6GL3i3fcx5EYk1uXuKkMWlAba78JfHwlZygIgDl3KVQASzQiDX3ps+oB4zcpzBUl4xnu8MtDOIyS/h9UBAQQiACBRN+X88z0/Wy8URWS8n1NgPW0wJ2aQk8qDQN2IcKvDbQEFJVEhAzDVT9DdQgpuX402JPXzSCyuNQ951fB1O/W+75wtka88Ua4iBgMw1U/Q3UIKbl+NNiT180gsrjUPedXwdTv1vu+cLZGvPBhzxdoKVAAAgAAAAIAAAACAAAAAAAAAAAAAAAA='),
        ]
        for with_witness_utxo, utxo_only, scriptcode_hex, expected in cases:
            scriptcode, scriptcode_len = make_cbuffer(scriptcode_hex)
            sigs = []
            for b64 in [with_witness_utxo, utxo_only]:
                psbt = self.parse_base64(b64)
                self.assertEqual(wally_psbt_sign(psbt, priv, priv_len, FLAG_GRIND_R), WALLY_OK)
                der, der_len = make_cbuffer('00' * 80)
                ret, written = wally_psbt_get_input_signature(psbt, 0, 0, der, der_len)
                self.assertEqual(ret, WALLY_OK)
                sigs.append(der[:written])
                # The signature must verify against the BIP143 digest of the input
                tx = pointer(wally_tx())
                self.assertEqual(wally_psbt_extract(psbt, EXTRACT_NON_FINAL, tx), WALLY_OK)
                digest, digest_len = make_cbuffer('00' * 32)
                ret = wally_tx_get_btc_signature_hash(tx, 0, scriptcode, scriptcode_len, AMOUNT,
                                                      SIGHASH_ALL, TX_FLAG_USE_WITNESS, digest, digest_len)
                self.assertEqual(ret, WALLY_OK)
                sig, sig_len = make_cbuffer('00' * 64)
                self.assertEqual(wally_ec_sig_from_der(der, written - 1, sig, sig_len), WALLY_OK)
                self.assertEqual(wally_ec_sig_verify(pub, pub_len, digest, digest_len, EC_FLAG_ECDSA, sig, sig_len), WALLY_OK)
                wally_tx_free(tx)
                if b64 == utxo_only:
                    self.assertEqual(self.to_base64(psbt), expected)
                    self.assertEqual(wally_psbt_finalize(psbt, 0), WALLY_OK)
                wally_psbt_free(psbt)
            # Same key, same tx, same prevout: the two signatures must be identical
            self.assertEqual(sigs[0], sigs[1])

        # A full previous tx whose txid does not match the input must not be signed from
        psbt = self.parse_base64('cHNidP8BAHECAAAAAQxuGqyWuXswoO+9JP28P/bNV3rmmdNMmCHmpQZOgnLlAAAAAAD9////AmDqAAAAAAAAFgAUERERERERERERERERERERERERERFYmAAAAAAAABYAFD40mF3Kb93J+zaZQOTH2OKHP1KcAAAAAAABAFIBAAAAATMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AaCGAQAAAAAAFgAUwM681sPTyox13F7GLr5VMw75EOIAAAAAIgYDMNVP0N1CCm5fjTYk9fNILK41D3nV8HU79b7vnC2RrzwYc8XaClQAAIAAAACAAAAAgAAAAAAAAAAAAAAA')
        self.assertEqual(wally_psbt_sign(psbt, priv, priv_len, FLAG_GRIND_R), WALLY_EINVAL)
        ret, num_sigs = wally_psbt_get_input_signatures_size(psbt, 0)
        self.assertEqual((ret, num_sigs), (WALLY_OK, 0))
        wally_psbt_free(psbt)

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

if __name__ == '__main__':
    unittest.main()
