"""Tests for PSBT wrappers"""
import unittest
from wallycore import *

SIG_BYTES = hex_to_bytes('30450220263325fcbd579f5a3d0c49aa96538d9562ee41dc690d50dcc5a0af4ba2b9efcf022100fd8d53c6be9b3f68c74eed559cca314e718df437b5c5c57668c5930e14140502')

SAMPLE = 'cHNidP8BAFICAAAAAZ38ZijCbFiZ/hvT3DOGZb/VXXraEPYiCXPfLTht7BJ2AQAAAAD/////AfA9zR0AAAAAFgAUezoAv9wU0neVwrdJAdCdpu8TNXkAAAAATwEENYfPAto/0AiAAAAAlwSLGtBEWx7IJ1UXcnyHtOTrwYogP/oPlMAVZr046QADUbdDiH7h1A3DKmBDck8tZFmztaTXPa7I+64EcvO8Q+IM2QxqT64AAIAAAACATwEENYfPAto/0AiAAAABuQRSQnE5zXjCz/JES+NTzVhgXj5RMoXlKLQH+uP2FzUD0wpel8itvFV9rCrZp+OcFyLrrGnmaLbyZnzB1nHIPKsM2QxqT64AAIABAACAAAEBKwBlzR0AAAAAIgAgLFSGEmxJeAeagU4TcV1l82RZ5NbMre0mbQUIZFuvpjIBBUdSIQKdoSzbWyNWkrkVNq/v5ckcOrlHPY5DtTODarRWKZyIcSEDNys0I07Xz5wf6l0F1EFVeSe+lUKxYusC4ass6AIkwAtSriIGAp2hLNtbI1aSuRU2r+/lyRw6uUc9jkO1M4NqtFYpnIhxENkMak+uAACAAAAAgAAAAAAiBgM3KzQjTtfPnB/qXQXUQVV5J76VQrFi6wLhqyzoAiTACxDZDGpPrgAAgAEAAIAAAAAAACICA57/H1R6HV+S36K6evaslxpL0DukpzSwMVaiVritOh75EO3kXMUAAACAAAAAgAEAAIAA'
SAMPLE_V2 = 'cHNidP8B+wQCAAAAAQIEewAAAAEEAQEBBQEBAAEOIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gAQ8EAQAAAAABAwiH1hIAAAAAAAEEIQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='


class PSBTTests(unittest.TestCase):

    def _throws(self, fn, psbt, *args):
        self.assertRaises(ValueError, lambda: fn(psbt, *args))

    def _try_invalid(self, fn, psbt, *args):
        self._throws(fn, None, 0, *args) # Null PSBT
        self._throws(fn, psbt, 1, *args) # Invalid index

    def _try_set(self, fn, psbt, valid_value, null_value=None):
        fn(psbt, 0, valid_value) # Set
        fn(psbt, 0, null_value) # Un-set
        self._try_invalid(fn, psbt, valid_value)

    def _try_get_set_i(self, setfn, clearfn, getfn, psbt, valid_value, invalid_value=None):
        self._try_invalid(setfn, psbt, valid_value)
        setfn(psbt, 0, valid_value) # Set
        self._try_invalid(getfn, psbt)
        ret = getfn(psbt, 0) # Get
        self.assertEqual(valid_value, ret)
        if clearfn:
            self._try_invalid(clearfn, psbt)
            clearfn(psbt, 0)
        if invalid_value is not None:
            self._throws(setfn, psbt, 0, invalid_value)

    def _try_get_set_b(self, setfn, getfn, lenfn, psbt, valid_value, null_value=None):
        self._try_set(setfn, psbt, valid_value, null_value)
        setfn(psbt, 0, valid_value) # Set
        self._try_invalid(lenfn, psbt)
        self._try_invalid(getfn, psbt)
        ret = getfn(psbt, 0) # Get
        self.assertEqual(valid_value, ret)

    def _try_get_set_m(self, setfn, sizefn, lenfn, getfn, findfn, psbt, valid_value, valid_item):
        self._try_set(setfn, psbt, valid_value, None)
        self._try_invalid(sizefn, psbt)
        self.assertEqual(sizefn(psbt, 0), 0)
        setfn(psbt, 0, valid_value) # Set
        self.assertEqual(sizefn(psbt, 0), 1) # 1 item in the map
        self._try_invalid(lenfn, psbt, 0)
        with self.assertRaises(ValueError):
            lenfn(psbt, 0, 1) # Invalid subindex
        map_val = getfn(psbt, 0, 0)
        self.assertTrue(len(map_val) > 0)
        self.assertEqual(lenfn(psbt, 0, 0), len(map_val))
        self._try_invalid(findfn, psbt, map_val)
        self.assertEqual(findfn(psbt, 0, valid_item), 1)


    def test_psbt(self):
        psbt = psbt_from_base64(SAMPLE)
        psbt2 = psbt_from_base64(SAMPLE_V2)

        # Roundtrip to/from bytes
        self.assertRaises(ValueError, lambda: psbt_to_bytes(None, 0))    # NULL PSBT
        self.assertRaises(ValueError, lambda: psbt_to_bytes(psbt, 0xff)) # Bad flags
        psbt_bytes = psbt_to_bytes(psbt, 0)
        psbt_tmp = psbt_from_bytes(psbt_bytes)
        self.assertEqual(hex_from_bytes(psbt_bytes),
                         hex_from_bytes(psbt_to_bytes(psbt_tmp, 0)))

        for fn, ret in [(psbt_get_version, 0),
                        (psbt_get_num_inputs, 1),
                        (psbt_get_num_outputs, 1)]:
            self.assertEqual(fn(psbt), ret)
            with self.assertRaises(ValueError):
                fn(None) # Null PSBT

        # Conversion to base64 should round trip
        self.assertEqual(psbt_to_base64(psbt, 0), SAMPLE)

        # Combining with ourselves shouldn't change the PSBT
        psbt_combine(psbt, psbt)
        self.assertEqual(psbt_to_base64(psbt, 0), SAMPLE)

        # Unique ID
        psbt_set_fallback_locktime(psbt2, 0xfffffffd)
        self._throws(psbt_get_id, None, 0)      # NULL PSBT
        self._throws(psbt_get_id, psbt, 0xff)   # Unknown flags
        self._throws(psbt_get_id, psbt2, 0xff)  # Unknown flags, v2
        for p, flags, expected_id in [
            (psbt,  0x0, '3d52f16feabb48bb5f7ec374fb11fd33c52871aa556a0424b205d769f46c17c6'),
            (psbt,  0x1, 'fa9614be7e1fcb6c94083643f49b3da40087ca36f6cf182d342d627261c12567'),
            (psbt,  0x2, '3d52f16feabb48bb5f7ec374fb11fd33c52871aa556a0424b205d769f46c17c6'),
            (psbt,  0x3, 'fa9614be7e1fcb6c94083643f49b3da40087ca36f6cf182d342d627261c12567'),
            (psbt2, 0x0, '1ef6f55dabf5e064733e2606403ba9ce82fea194d3a2c3072f17a01493f00063'),
            (psbt2, 0x1, '1ef6f55dabf5e064733e2606403ba9ce82fea194d3a2c3072f17a01493f00063'),
            (psbt2, 0x2, '2f7657fe56cd485ff00dc433722b8640ac88b86bf5a766b00b7f8cb2be016056'),
            (psbt2, 0x3, '2f7657fe56cd485ff00dc433722b8640ac88b86bf5a766b00b7f8cb2be016056')
            ]:
            self.assertEqual(hex_from_bytes(psbt_get_id(p, flags)), expected_id)

        # Test setters
        self._throws(psbt_get_global_tx, None)  # NULL PSBT
        self._throws(psbt_get_global_tx, psbt2) # V2, unsupported
        dummy_tx = psbt_get_global_tx(psbt)
        self.assertIsNotNone(dummy_tx)
        self._throws(psbt_set_global_tx, None, dummy_tx)  # NULL PSBT
        self._throws(psbt_set_global_tx, psbt2, dummy_tx) # V2, unsupported

        dummy_txout = tx_output_init(1234567, bytearray(b'\x00' * 33))

        dummy_witness = tx_witness_stack_init(5)
        self.assertIsNotNone(dummy_witness)

        dummy_bytes = bytearray(b'\x00' * 32)
        dummy_pubkey = bytearray(b'\x02'* EC_PUBLIC_KEY_LEN)
        dummy_fingerprint = bytearray(b'\x00' * BIP32_KEY_FINGERPRINT_LEN)
        dummy_path = [1234, 1234, 1234]
        dummy_sig = SIG_BYTES + bytearray(b'\x01')      # SIGHASH_ALL
        dummy_sig_0 = SIG_BYTES + bytearray(b'\x00')    # Invalid sighash 0
        dummy_sig_none = SIG_BYTES + bytearray(b'\x02') # SIGHASH_NONE
        dummy_sig_acp = SIG_BYTES + bytearray(b'\x80')  # SIGHASH_ANYONECANPAY
        dummy_sig_sacp = SIG_BYTES + bytearray(b'\x83') # SIGHASH_SINGLE|SIGHASH_ANYONECANPAY
        if is_elements_build():
            dummy_nonce = bytearray(b'\x00' * WALLY_TX_ASSET_CT_NONCE_LEN)
            dummy_bf = bytearray(b'\x00' * BLINDING_FACTOR_LEN)
            dummy_commitment = bytearray(b'\x00' * ASSET_COMMITMENT_LEN)
            dummy_asset = bytearray(b'\x00' * ASSET_TAG_LEN)

        dummy_keypaths = map_init(0)
        self.assertIsNotNone(dummy_keypaths)
        map_add_keypath_item(dummy_keypaths, dummy_pubkey, dummy_fingerprint, dummy_path)
        self.assertEqual(map_find(dummy_keypaths, dummy_pubkey), 1)

        empty_signatures = map_init(0)
        dummy_signatures = map_init(0)
        self.assertIsNotNone(dummy_signatures)
        map_add(dummy_signatures, dummy_pubkey, dummy_sig)
        self.assertEqual(map_find(dummy_signatures, dummy_pubkey), 1)

        dummy_unknowns = map_init(1)
        self.assertIsNotNone(dummy_unknowns)
        map_add(dummy_unknowns, dummy_pubkey, dummy_fingerprint)
        self.assertEqual(map_find(dummy_unknowns, dummy_pubkey), 1)

        # V2: Global Tx Version
        self._throws(psbt_get_tx_version, None) # NULL PSBT
        self._throws(psbt_get_tx_version, psbt), # V0, unsupported
        self.assertEqual(psbt_get_tx_version(psbt2), 123)

        self._throws(psbt_set_tx_version, None, 3)  # NULL PSBT
        self._throws(psbt_set_tx_version, psbt, 3)  # V0, unsupported
        self._throws(psbt_set_tx_version, psbt2, 1) # Must be >=2

        psbt_set_tx_version(psbt2, 3)
        self.assertEqual(psbt_get_tx_version(psbt2), 3)

        # V2: Fallback Locktime
        self._throws(psbt_get_fallback_locktime, None)    # NULL PSBT
        self._throws(psbt_get_fallback_locktime, psbt),   # V0, unsupported
        self._throws(psbt_set_fallback_locktime, None, 0xfffffffe)  # NULL PSBT
        self._throws(psbt_set_fallback_locktime, psbt, 0xfffffffe), # V0, unsupported
        self._throws(psbt_has_fallback_locktime, None)    # NULL PSBT
        self._throws(psbt_has_fallback_locktime, psbt),   # V0, unsupported
        self._throws(psbt_clear_fallback_locktime, None)  # NULL PSBT
        self._throws(psbt_clear_fallback_locktime, psbt), # V0, unsupported

        psbt_set_fallback_locktime(psbt2, 0xfffffffd)
        self.assertEqual(psbt_get_fallback_locktime(psbt2), 0xfffffffd)
        self.assertTrue(psbt_has_fallback_locktime(psbt2))

        psbt_clear_fallback_locktime(psbt2)
        self.assertFalse(psbt_has_fallback_locktime(psbt2))

        # V2: Modifiable flags
        self._throws(psbt_set_tx_modifiable_flags, None, 3)    # NULL PSBT
        self._throws(psbt_set_tx_modifiable_flags, psbt, 3)    # Non v2 PSBT
        self._throws(psbt_set_tx_modifiable_flags, psbt2, 255) # Bad flags
        self._throws(psbt_get_tx_modifiable_flags, None)       # NULL PSBT
        self._throws(psbt_get_tx_modifiable_flags, psbt)       # Non v2 PSBT
        psbt_set_tx_modifiable_flags(psbt2, 1)
        self.assertEqual(psbt_get_tx_modifiable_flags(psbt2), 1)

        #
        # Inputs
        #
        for p in [psbt, psbt2]:
            self._try_set(psbt_set_input_utxo, p, dummy_tx)
            self._try_invalid(psbt_get_input_utxo, p)
            self._try_set(psbt_set_input_witness_utxo, p, dummy_txout)
            self._try_invalid(psbt_get_input_witness_utxo, p)
            self._try_get_set_b(psbt_set_input_redeem_script,
                                psbt_get_input_redeem_script,
                                psbt_get_input_redeem_script_len, p, dummy_bytes)
            self._try_get_set_b(psbt_set_input_witness_script,
                                psbt_get_input_witness_script,
                                psbt_get_input_witness_script_len, p, dummy_bytes)
            self._try_get_set_b(psbt_set_input_final_scriptsig,
                                psbt_get_input_final_scriptsig,
                                psbt_get_input_final_scriptsig_len, p, dummy_bytes)
            self._try_set(psbt_set_input_final_witness, p, dummy_witness)
            self._try_invalid(psbt_get_input_final_witness, p)
            self._try_get_set_m(psbt_set_input_keypaths,
                                psbt_get_input_keypaths_size,
                                psbt_get_input_keypath_len,
                                psbt_get_input_keypath,
                                psbt_find_input_keypath,
                                p, dummy_keypaths, dummy_pubkey)
            self._try_get_set_m(psbt_set_input_signatures,
                                psbt_get_input_signatures_size,
                                psbt_get_input_signature_len,
                                psbt_get_input_signature,
                                psbt_find_input_signature,
                                p, dummy_signatures, dummy_pubkey)
            self._try_invalid(psbt_add_input_signature, p, dummy_pubkey, dummy_sig)
            self._try_invalid(psbt_add_input_signature, p, dummy_pubkey, dummy_sig)
            self._throws(psbt_add_input_signature, p, 0, None, dummy_sig)            # NULL pubkey
            self._throws(psbt_add_input_signature, p, 0, dummy_sig, dummy_sig)       # Invalid pubkey
            self._throws(psbt_add_input_signature, p, 0, dummy_pubkey, None)         # NULL sig
            self._throws(psbt_add_input_signature, p, 0, dummy_pubkey, dummy_pubkey) # Invalid sig
            self._throws(psbt_add_input_signature, p, 0, dummy_pubkey, dummy_sig_0)  # Invalid signature sighash
            psbt_set_input_signatures(p, 0, empty_signatures)
            self.assertEqual(psbt_get_input_signatures_size(p, 0), 0)
            psbt_set_input_sighash(p, 0, 0x3)
            self._throws(psbt_add_input_signature, p, 0, dummy_pubkey, dummy_sig)    # Incompatible sighash
            psbt_set_input_sighash(p, 0, 0x0)
            psbt_add_input_signature(p, 0, dummy_pubkey, dummy_sig)                  # Compatible, works
            self.assertEqual(psbt_get_input_signatures_size(p, 0), 1)
            # Test setting various sighash types and resulting modifiable flags for v2
            PSBT_TXMOD_BOTH = WALLY_PSBT_TXMOD_INPUTS | WALLY_PSBT_TXMOD_OUTPUTS
            PSBT_TXMOD_INP_SINGLE = WALLY_PSBT_TXMOD_INPUTS | WALLY_PSBT_TXMOD_SINGLE
            for sig, modflags in [
                (dummy_sig,       0),                        # ALL -> Neither are modifiable
                (dummy_sig_none,  WALLY_PSBT_TXMOD_OUTPUTS), # NONE -> Outputs remain modifiable
                (dummy_sig_acp,   WALLY_PSBT_TXMOD_INPUTS),  # ANYONECANPAY -> Inputs remain modifiable
                # SINGLE | ANYONECANPAY -> Inputs remain modifiable and SINGLE flags set
                (dummy_sig_sacp,  PSBT_TXMOD_INP_SINGLE),
                ]:
                psbt_set_input_signatures(p, 0, empty_signatures)
                if p == psbt2:
                    psbt_set_tx_modifiable_flags(p, PSBT_TXMOD_BOTH)
                psbt_add_input_signature(p, 0, dummy_pubkey, sig)
                if p == psbt2:
                    self.assertEqual(psbt_get_tx_modifiable_flags(p), modflags)

            self._try_get_set_m(psbt_set_input_unknowns,
                                psbt_get_input_unknowns_size,
                                psbt_get_input_unknown_len,
                                psbt_get_input_unknown,
                                psbt_find_input_unknown,
                                p, dummy_unknowns, dummy_pubkey)
            psbt_set_input_signatures(p, 0, empty_signatures)
            self._try_get_set_i(psbt_set_input_sighash, None,
                                psbt_get_input_sighash, p, 0xff) # FIXME 0x100 as invalid_value should fail

        # V2: Previous txid
        self._throws(psbt_set_input_previous_txid, psbt, 0, dummy_bytes) # Non v2 PSBT
        self._throws(psbt_set_input_previous_txid, psbt2, 0, dummy_sig)  # Bad Length
        self._throws(psbt_get_input_previous_txid, psbt, 0)              # Non v2 PSBT
        self._throws(psbt_get_input_previous_txid_len, psbt, 0)          # Non v2 PSBT
        self._try_get_set_b(psbt_set_input_previous_txid,
                            psbt_get_input_previous_txid,
                            psbt_get_input_previous_txid_len, psbt2, dummy_bytes)

        # V2: Output Index
        self._throws(psbt_set_input_output_index, psbt, 0, 1234) # Non v2 PSBT
        self._throws(psbt_get_input_output_index, psbt, 0)       # Non v2 PSBT
        self._try_get_set_i(psbt_set_input_output_index,
                            None,
                            psbt_get_input_output_index, psbt2, 1234)

        # V2: Sequence
        self._throws(psbt_set_input_sequence, psbt, 0, 1234) # Non v2 PSBT
        self._throws(psbt_clear_input_sequence, psbt, 0)     # Non v2 PSBT
        self._throws(psbt_get_input_sequence, psbt, 0)       # Non v2 PSBT
        self._try_get_set_i(psbt_set_input_sequence,
                            psbt_clear_input_sequence,
                            psbt_get_input_sequence, psbt2, 1234)
        # If no sequence is present, it defaults to final (0xffffffff)
        psbt_clear_input_sequence(psbt2, 0)
        self.assertEqual(psbt_get_input_sequence(psbt2, 0), 0xffffffff)

        # V2: Required Lock Height/Time
        heightfns = (psbt_get_input_required_lockheight, psbt_set_input_required_lockheight,
            psbt_has_input_required_lockheight, psbt_clear_input_required_lockheight)
        timefns = (psbt_get_input_required_locktime, psbt_set_input_required_locktime,
            psbt_has_input_required_locktime, psbt_clear_input_required_locktime)
        for g_fn, s_fn, h_fn, c_fn, v in [(*heightfns, 1234), (*timefns, 500000001)]:
            self._throws(s_fn, psbt, 0, v)  # Non v2 PSBT
            self._throws(s_fn, psbt2, 0, 0) # Zero value
            self._throws(g_fn, psbt, 0)     # Non v2 PSBT
            self._throws(h_fn, psbt, 0)     # Non v2 PSBT
            self._throws(c_fn, psbt, 0)     # Non v2 PSBT
            self._try_get_set_i(s_fn, c_fn, g_fn, psbt2, v)

        if is_elements_build():
            self._try_set(psbt_set_input_value, psbt, 1234567, 0)
            self._try_invalid(psbt_has_input_value, psbt)
            self._try_invalid(psbt_get_input_value, psbt)
            self._try_invalid(psbt_clear_input_value, psbt)
            self.assertEqual(psbt_has_input_value(psbt, 0), 1)
            psbt_clear_input_value(psbt, 0)
            self.assertEqual(psbt_has_input_value(psbt, 0), 0)
            self._try_get_set_b(psbt_set_input_vbf,
                                psbt_get_input_vbf,
                                psbt_get_input_vbf_len, psbt, dummy_bf)
            self._try_get_set_b(psbt_set_input_asset,
                                psbt_get_input_asset,
                                psbt_get_input_asset_len, psbt, dummy_asset)
            self._try_get_set_b(psbt_set_input_abf,
                                psbt_get_input_abf,
                                psbt_get_input_abf_len, psbt, dummy_bf)
            self._try_set(psbt_set_input_pegin_tx, psbt, dummy_tx)
            self._try_invalid(psbt_get_input_pegin_tx, psbt)
            self._try_get_set_b(psbt_set_input_txoutproof,
                                psbt_get_input_txoutproof,
                                psbt_get_input_txoutproof_len, psbt, dummy_bytes)
            self._try_get_set_b(psbt_set_input_genesis_blockhash,
                                psbt_get_input_genesis_blockhash,
                                psbt_get_input_genesis_blockhash_len, psbt, dummy_bytes)
            self._try_get_set_b(psbt_set_input_claim_script,
                                psbt_get_input_claim_script,
                                psbt_get_input_claim_script_len, psbt, dummy_bytes)

        #
        # Outputs
        #
        for p in [psbt, psbt2]:
            self._try_get_set_b(psbt_set_output_redeem_script,
                                psbt_get_output_redeem_script,
                                psbt_get_output_redeem_script_len, p, dummy_bytes)
            self._try_get_set_b(psbt_set_output_witness_script,
                                psbt_get_output_witness_script,
                                psbt_get_output_witness_script_len, p, dummy_bytes)
            self._try_get_set_m(psbt_set_output_keypaths,
                                psbt_get_output_keypaths_size,
                                psbt_get_output_keypath_len,
                                psbt_get_output_keypath,
                                psbt_find_output_keypath,
                                p, dummy_keypaths, dummy_pubkey)
            self._try_get_set_m(psbt_set_output_unknowns,
                                psbt_get_output_unknowns_size,
                                psbt_get_output_unknown_len,
                                psbt_get_output_unknown,
                                psbt_find_output_unknown,
                                p, dummy_unknowns, dummy_pubkey)
            if is_elements_build():
                self._try_get_set_b(psbt_set_output_blinding_pubkey,
                                    psbt_get_output_blinding_pubkey,
                                    psbt_get_output_blinding_pubkey_len, p, dummy_pubkey)
                self._try_get_set_b(psbt_set_output_value_commitment,
                                    psbt_get_output_value_commitment,
                                    psbt_get_output_value_commitment_len, p, dummy_commitment)
                self._try_get_set_b(psbt_set_output_vbf,
                                    psbt_get_output_vbf,
                                    psbt_get_output_vbf_len, p, dummy_bf)
                self._try_get_set_b(psbt_set_output_asset_commitment,
                                    psbt_get_output_asset_commitment,
                                    psbt_get_output_asset_commitment_len, p, dummy_commitment)
                self._try_get_set_b(psbt_set_output_abf,
                                    psbt_get_output_abf,
                                    psbt_get_output_abf_len, p, dummy_bf)
                self._try_get_set_b(psbt_set_output_nonce,
                                    psbt_get_output_nonce,
                                    psbt_get_output_nonce_len, p, dummy_nonce)
                self._try_get_set_b(psbt_set_output_rangeproof,
                                    psbt_get_output_rangeproof,
                                    psbt_get_output_rangeproof_len, p, dummy_bytes)
                self._try_get_set_b(psbt_set_output_surjectionproof,
                                    psbt_get_output_surjectionproof,
                                    psbt_get_output_surjectionproof_len, p, dummy_bytes)

        # V2: Amount
        self._throws(psbt_set_output_amount, psbt, 0, 1234)   # Non v2 PSBT
        self._throws(psbt_get_output_amount, psbt, 0)         # Non v2 PSBT
        self._throws(psbt_has_output_amount, None, 0)         # NULL PSBT
        self._throws(psbt_has_output_amount, psbt, 0)         # Non v2 PSBT
        self._throws(psbt_has_output_amount, psbt2, 1)        # Invalid Index
        self.assertEqual(psbt_has_output_amount(psbt2, 0), 1) # Non v2 PSBT
        self._throws(psbt_clear_output_amount, psbt, 0)       # Non v2 PSBT
        self._try_get_set_i(psbt_set_output_amount,
                            psbt_clear_output_amount,
                            psbt_get_output_amount, psbt2, 1234)

        # V2: Script
        self._throws(psbt_set_output_script, psbt, 0, dummy_bytes) # Non v2 PSBT
        self._throws(psbt_get_output_script, psbt, 0)              # Non v2 PSBT
        self._throws(psbt_get_output_script_len, psbt, 0)          # Non v2 PSBT
        self._try_get_set_b(psbt_set_output_script,
                            psbt_get_output_script,
                            psbt_get_output_script_len, psbt2, dummy_bytes)


if __name__ == '__main__':
    unittest.main()
