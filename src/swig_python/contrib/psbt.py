"""Tests for PSBT wrappers"""
import unittest
from wallycore import *

PSBT_TXMOD_BOTH = WALLY_PSBT_TXMOD_INPUTS | WALLY_PSBT_TXMOD_OUTPUTS
PSBT_TXMOD_INP_SINGLE = WALLY_PSBT_TXMOD_INPUTS | WALLY_PSBT_TXMOD_SINGLE

SIG_BYTES = hex_to_bytes('30450220263325fcbd579f5a3d0c49aa96538d9562ee41dc690d50dcc5a0af4ba2b9efcf022100fd8d53c6be9b3f68c74eed559cca314e718df437b5c5c57668c5930e14140502')

SAMPLE = 'cHNidP8BAFICAAAAAZ38ZijCbFiZ/hvT3DOGZb/VXXraEPYiCXPfLTht7BJ2AQAAAAD/////AfA9zR0AAAAAFgAUezoAv9wU0neVwrdJAdCdpu8TNXkAAAAATwEENYfPAto/0AiAAAAAlwSLGtBEWx7IJ1UXcnyHtOTrwYogP/oPlMAVZr046QADUbdDiH7h1A3DKmBDck8tZFmztaTXPa7I+64EcvO8Q+IM2QxqT64AAIAAAACATwEENYfPAto/0AiAAAABuQRSQnE5zXjCz/JES+NTzVhgXj5RMoXlKLQH+uP2FzUD0wpel8itvFV9rCrZp+OcFyLrrGnmaLbyZnzB1nHIPKsM2QxqT64AAIABAACAAAEBKwBlzR0AAAAAIgAgLFSGEmxJeAeagU4TcV1l82RZ5NbMre0mbQUIZFuvpjIBBUdSIQKdoSzbWyNWkrkVNq/v5ckcOrlHPY5DtTODarRWKZyIcSEDNys0I07Xz5wf6l0F1EFVeSe+lUKxYusC4ass6AIkwAtSriIGAp2hLNtbI1aSuRU2r+/lyRw6uUc9jkO1M4NqtFYpnIhxENkMak+uAACAAAAAgAAAAAAiBgM3KzQjTtfPnB/qXQXUQVV5J76VQrFi6wLhqyzoAiTACxDZDGpPrgAAgAEAAIAAAAAAACICA57/H1R6HV+S36K6evaslxpL0DukpzSwMVaiVritOh75EO3kXMUAAACAAAAAgAEAAIAA'
SAMPLE_V2 = 'cHNidP8B+wQCAAAAAQIEewAAAAEEAQEBBQEBAAEOIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gAQ8EAQAAAAABAwiH1hIAAAAAAAEEIQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
SAMPLE_PSET = 'cHNldP8B+wQCAAAAAQIEAgAAAAEEAQEBBQEBAQYBAwf8BHBzZXQBAQEAAQ4gnfxmKMJsWJn+G9PcM4Zlv9VdetoQ9iIJc98tOG3sEnYBDwQBAAAAARAE////AAABAwjwPc0dAAAAAAEEFgAUezoAv9wU0neVwrdJAdCdpu8TNXkA'


class PSBTTests(unittest.TestCase):

    def _throws(self, fn, psbt, *args):
        self.assertRaises(ValueError, lambda: fn(psbt, *args))

    def _try_invalid(self, fn, psbt, *args):
        self._throws(fn, None, 0, *args) # Null PSBT
        self._throws(fn, psbt, 1, *args) # Invalid index

    def _round_trip(self, psbt):
        psbt_bytes = psbt_to_bytes(psbt, 0)
        deserialized = psbt_from_bytes(psbt_bytes)
        new_bytes = psbt_to_bytes(deserialized, 0)
        self.assertEqual(psbt_bytes, new_bytes)

    def _try_set(self, fn, psbt, valid_value, null_value=None, mandatory=False, allow_null=True, roundtrip=True):
        if roundtrip:
            self._round_trip(psbt)
        fn(psbt, 0, valid_value) # Set
        if roundtrip:
            self._round_trip(psbt)
        if allow_null:
            fn(psbt, 0, null_value) # Un-set
            if mandatory:
                fn(psbt, 0, valid_value) # Set
            elif roundtrip:
                self._round_trip(psbt)
        else:
            self._throws(fn, psbt, 0, null_value)
        self._try_invalid(fn, psbt, valid_value)

    def _try_get_set_i(self, setfn, clearfn, getfn, psbt, valid_value, invalid_value=None, mandatory=False):
        self._try_invalid(setfn, psbt, valid_value)
        setfn(psbt, 0, valid_value) # Set
        self._round_trip(psbt)
        self._try_invalid(getfn, psbt)
        ret = getfn(psbt, 0) # Get
        self.assertEqual(valid_value, ret)
        if clearfn:
            self._try_invalid(clearfn, psbt)
            clearfn(psbt, 0)
            if mandatory:
                setfn(psbt, 0, valid_value) # Set Again
            else:
                self._round_trip(psbt)
        if invalid_value is not None:
            self._throws(setfn, psbt, 0, invalid_value)

    def _try_get_set_b(self, setfn, getfn, lenfn, psbt, valid_value, null_value=None, mandatory=False, roundtrip=True):
        self._try_set(setfn, psbt, valid_value, null_value, mandatory, roundtrip=roundtrip)
        setfn(psbt, 0, valid_value) # Set
        if roundtrip:
            self._round_trip(psbt)
        if lenfn:
            self._try_invalid(lenfn, psbt)
        self._try_invalid(getfn, psbt)
        ret = getfn(psbt, 0) # Get
        self.assertEqual(valid_value, ret)

    def _try_get_set_m(self, setfn, sizefn, lenfn, getfn, findfn, psbt,
                       valid_value, valid_item):
        self._try_set(setfn, psbt, valid_value, None, allow_null=False)
        self._try_invalid(sizefn, psbt)
        setfn(psbt, 0, valid_value) # Set
        self.assertEqual(sizefn(psbt, 0), 1) # 1 item in the map
        self._try_invalid(lenfn, psbt, 0)
        self._throws(lenfn, psbt, 0, 1) # Invalid subindex
        map_val = getfn(psbt, 0, 0)
        self.assertTrue(len(map_val) > 0)
        self.assertEqual(lenfn(psbt, 0, 0), len(map_val))
        self._try_invalid(findfn, psbt, map_val)
        self.assertEqual(findfn(psbt, 0, valid_item), 1)

    def _try_get_set_global_i(self, setfn, clearfn, getfn, psbt, valid_value):
        self._throws(setfn, None, valid_value) # Null PSBT
        setfn(psbt, valid_value) # Set
        self._round_trip(psbt)
        self._throws(getfn, None) # Null PSBT
        ret = getfn(psbt) # Get
        self.assertEqual(valid_value, ret)
        if clearfn:
            clearfn(psbt)
            self._round_trip(psbt)

    def _try_get_set_global_m(self, setfn, sizefn, lenfn, getfn, findfn, psbt, valid_value, valid_item):
        self._throws(setfn, None, valid_value) # Null PSBT
        self._throws(setfn, psbt, None) # Null PSBT
        self._throws(sizefn, None) # Null PSBT
        self.assertEqual(sizefn(psbt), 0)
        setfn(psbt, valid_value) # Set
        self._round_trip(psbt)
        self.assertEqual(sizefn(psbt), 1) # 1 item in the map
        if lenfn:
            self._throws(lenfn, None, 0) # Null PSBT
        map_val = getfn(psbt, 0)
        self.assertTrue(len(map_val) > 0)
        if lenfn:
            self.assertEqual(lenfn(psbt, 0), len(map_val))
        self._throws(findfn, None, map_val) # Null PSBT
        self.assertEqual(findfn(psbt, valid_item), 1)

    def test_add_remove(self):
        psbt = psbt_from_base64(SAMPLE)
        psbt2 = psbt_from_base64(SAMPLE_V2)

        for p in [psbt, psbt2]:
            self._throws(psbt_remove_input, None, 1) # NULL PSBT
            self._throws(psbt_remove_input, p, 1)    # Invalid index
            if p == psbt2:
               # Removing the last SIGHASH_SINGLE input removes PSBT_TXMOD_SINGLE
               psbt_set_tx_modifiable_flags(p, PSBT_TXMOD_BOTH | WALLY_PSBT_TXMOD_SINGLE)
               psbt_set_input_sighash(p, 0, WALLY_SIGHASH_SINGLE)
            psbt_remove_input(p, 0)
            if p == psbt2:
               self.assertEqual(psbt_get_tx_modifiable_flags(p), PSBT_TXMOD_BOTH)
            self._throws(psbt_remove_input, p, 0)    # Invalid index

    def test_psbt(self):
        psbt = psbt_from_base64(SAMPLE)
        psbt2 = psbt_from_base64(SAMPLE_V2)
        pset2 = psbt_from_base64(SAMPLE_PSET)
        clones = []

        self._throws(psbt_is_elements, None) # NULL PSBT
        for p, is_pset in [(psbt, False), (psbt2, False), (pset2, True)]:
            self.assertEqual(psbt_is_elements(p), is_pset)

        # Roundtrip to/from bytes
        self._throws(psbt_to_bytes, None, 0)    # NULL PSBT
        self._throws(psbt_to_bytes, psbt, 0xff) # Bad flags
        for p in [psbt, psbt2]:
            psbt_bytes = psbt_to_bytes(p, 0)
            psbt_tmp = psbt_from_bytes(psbt_bytes)
            self.assertEqual(hex_from_bytes(psbt_bytes),
                             hex_from_bytes(psbt_to_bytes(psbt_tmp, 0)))

            for fn, ret in [(psbt_get_version, 0 if p == psbt else 2),
                            (psbt_get_num_inputs, 1),
                            (psbt_get_num_outputs, 1)]:
                self.assertEqual(fn(p), ret)
                self._throws(fn, None) # Null PSBT

            sample = SAMPLE if p == psbt else SAMPLE_V2

            # Conversion to base64 should round trip
            self.assertEqual(psbt_to_base64(p, 0), sample)

            # Combining with ourselves shouldn't change the PSBT
            psbt_combine(p, p)
            self.assertEqual(psbt_to_base64(p, 0), sample)

            # Cloning shouldn't change the PSBT
            self._throws(psbt_clone, None, 0)  # NULL PSBT
            self._throws(psbt_clone, p, 0xff)  # Invalid flags
            clones.append(psbt_clone(p, 0))
            self.assertEqual(psbt_to_base64(clones[-1], 0), sample)

        # Upgrade/downgrade versions
        self._throws(psbt_set_version, None, 0, 0)     # NULL PSBT
        self._throws(psbt_set_version, psbt2, 0xff, 0) # Unknown flags
        self._throws(psbt_set_version, psbt2, 0, 3)    # Unknown version
        # Upgrading v0 to v2 is not yet supported
        self.assertRaises(RuntimeError, lambda: psbt_set_version(psbt, 0, 2))
        # Downgrade v2 to v0
        psbt_set_version(clones[1], 0, 0)

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

        # Locktime calculation
        self._throws(psbt_get_locktime, None)  # NULL PSBT
        self._throws(psbt_get_locktime, psbt)  # V0, unsupported
        self.assertEqual(psbt_get_locktime(psbt2), 0xfffffffd) # Returns fallback set above

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
        dummy_txid = bytearray(b'\x33' * 32)
        dummy_pubkey = hex_to_bytes('038575eb35e18fb168a913d8b49af50204f4f73627f6f7884f1be11e354664de8b')
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
            dummy_commitment = bytearray(b'\x44' * ASSET_COMMITMENT_LEN)
            dummy_asset = bytearray(b'\x00' * ASSET_TAG_LEN)
            dummy_nonce = bytearray(b'\x77' * ASSET_TAG_LEN)

        dummy_keypaths = map_keypath_public_key_init(1)
        self.assertIsNotNone(dummy_keypaths)
        map_keypath_add(dummy_keypaths, dummy_pubkey, dummy_fingerprint, dummy_path)
        self.assertEqual(map_find(dummy_keypaths, dummy_pubkey), 1)

        empty_signatures = map_init(0, None)
        dummy_signatures = map_init(0, None) # TODO: pubkey to sig map init
        self.assertIsNotNone(dummy_signatures)
        map_add(dummy_signatures, dummy_pubkey, dummy_sig)
        self.assertEqual(map_find(dummy_signatures, dummy_pubkey), 1)

        dummy_unknowns = map_init(1, None)
        self.assertIsNotNone(dummy_unknowns)
        dummy_unknown_key = bytearray(b'\x55' * 32)
        map_add(dummy_unknowns, dummy_unknown_key, dummy_fingerprint)
        self.assertEqual(map_find(dummy_unknowns, dummy_unknown_key), 1)

        dummy_offsets = map_init(1, None)
        self.assertIsNotNone(dummy_offsets)
        map_add(dummy_offsets, dummy_bytes, None)

        # V2: Global Tx Version
        self._throws(psbt_set_tx_version, psbt2, 1) # Must be >=2
        self._throws(psbt_set_tx_version, psbt, 3)  # V0, unsupported

        self._try_get_set_global_i(psbt_set_fallback_locktime,
                                   psbt_clear_fallback_locktime,
                                   psbt_get_fallback_locktime, psbt2, 3)

        # V2: Fallback Locktime
        self._throws(psbt_set_fallback_locktime, psbt, 0xfffffffe), # V0, unsupported
        self._throws(psbt_has_fallback_locktime, psbt),   # V0, unsupported
        self._throws(psbt_clear_fallback_locktime, psbt), # V0, unsupported

        self._try_get_set_global_i(psbt_set_fallback_locktime,
                                   psbt_clear_fallback_locktime,
                                   psbt_get_fallback_locktime, psbt2, 0xfffffffd)

        # V2: Modifiable flags
        self._throws(psbt_set_tx_modifiable_flags, psbt, 3)     # Non v2 PSBT
        self._throws(psbt_get_tx_modifiable_flags, psbt)        # Non v2 PSBT
        self._throws(psbt_set_tx_modifiable_flags, psbt2, 255)  # Invalid Value

        self._try_get_set_global_i(psbt_set_tx_modifiable_flags, None,
                                   psbt_get_tx_modifiable_flags, psbt2, 1)

        if is_elements_build():
            # Scalar Offsets
            self._try_get_set_global_m(psbt_set_global_scalars,
                                       psbt_get_global_scalars_size,
                                       None,
                                       psbt_get_global_scalar,
                                       psbt_find_global_scalar,
                                       pset2, dummy_offsets, dummy_bytes)

            # Elements TX Modifiable Flags
            self._try_get_set_global_i(psbt_set_pset_modifiable_flags, None,
                                       psbt_get_pset_modifiable_flags, pset2, 1)

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
            psbt_set_input_sighash(p, 0, WALLY_SIGHASH_SINGLE)
            self._throws(psbt_add_input_signature, p, 0, dummy_pubkey, dummy_sig)    # Incompatible sighash
            psbt_set_input_sighash(p, 0, 0x0)
            psbt_add_input_signature(p, 0, dummy_pubkey, dummy_sig)                  # Compatible, works
            self.assertEqual(psbt_get_input_signatures_size(p, 0), 1)
            # Test setting various sighash types and resulting modifiable flags for v2
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
                                p, dummy_unknowns, dummy_unknown_key)
            psbt_set_input_signatures(p, 0, empty_signatures)
            self._try_get_set_i(psbt_set_input_sighash, None,
                                psbt_get_input_sighash, p, 0xff) # FIXME 0x100 as invalid_value should fail

        #
        # Inputs: PSBT V2
        #
        # V2: Previous txid
        self._throws(psbt_set_input_previous_txid, psbt, 0, dummy_txid) # Non v2 PSBT
        self._throws(psbt_set_input_previous_txid, psbt2, 0, dummy_sig)  # Bad Length
        self._throws(psbt_get_input_previous_txid, psbt, 0)              # Non v2 PSBT
        self._try_get_set_b(psbt_set_input_previous_txid,
                            psbt_get_input_previous_txid,
                            None, psbt2, dummy_txid, mandatory=True)

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

        #
        # Inputs: PSET
        #
        if is_elements_build():
            # PSET: Unblinded issuance amount/inflation keys/pegin amount
            for setfn, getfn in [
                (psbt_set_input_issuance_amount, psbt_get_input_issuance_amount),
                (psbt_set_input_inflation_keys,  psbt_get_input_inflation_keys),
                (psbt_set_input_pegin_amount, psbt_get_input_pegin_amount)]:
                self._throws(setfn, psbt, 0, 1234) # Non v2 PSBT
                self._throws(getfn, psbt, 0)       # Non v2 PSBT
                self._try_get_set_i(setfn, None, getfn, pset2, 1234)

            # Clear amounts to allow round-tripping
            psbt_set_input_issuance_amount(pset2, 0, 0)
            psbt_set_input_inflation_keys(pset2, 0, 0)

            cases = [
                # PSET: blinded issuance amount (issuance amount commitment)
                (psbt_set_input_issuance_amount_commitment,
                 psbt_get_input_issuance_amount_commitment,
                 psbt_clear_input_issuance_amount_commitment, dummy_commitment, dummy_txid),
                # PSET: blinded issuance amount rangeproof
                (psbt_set_input_issuance_amount_rangeproof, psbt_get_input_issuance_amount_rangeproof,
                 psbt_clear_input_issuance_amount_rangeproof, dummy_bytes, None),
                # PSET: issuance blinding nonce
                (psbt_set_input_issuance_blinding_nonce,
                 psbt_get_input_issuance_blinding_nonce,
                 psbt_clear_input_issuance_blinding_nonce, dummy_nonce, dummy_commitment),
                # PSET: issuance blinding entropy
                (psbt_set_input_issuance_asset_entropy,
                 psbt_get_input_issuance_asset_entropy,
                 psbt_clear_input_issuance_asset_entropy, dummy_nonce, dummy_commitment),
                # PSET: blinded issuance amount value rangeproof
                #       (Confusing: this proves the blinded issuance amount matches
                #        the unblinded amount, for constructors/blinders use)
                (psbt_set_input_issuance_amount_blinding_rangeproof,
                 psbt_get_input_issuance_amount_blinding_rangeproof,
                 psbt_clear_input_issuance_amount_blinding_rangeproof, dummy_bytes, None),
                # PSET: peg-in claim script
                (psbt_set_input_pegin_claim_script, psbt_get_input_pegin_claim_script,
                 psbt_clear_input_pegin_claim_script, dummy_bytes, None),
                # PSET: peg-in genesis blockhash
                (psbt_set_input_pegin_genesis_blockhash, psbt_get_input_pegin_genesis_blockhash,
                 psbt_clear_input_pegin_genesis_blockhash, dummy_txid, dummy_commitment),
                # PSET: peg-in txout proof
                (psbt_set_input_pegin_txout_proof, psbt_get_input_pegin_txout_proof,
                 psbt_clear_input_pegin_txout_proof, dummy_bytes, None),
                # PSET: blinded number of inflation keys (issuance keys commitment)
                (psbt_set_input_inflation_keys_commitment, psbt_get_input_inflation_keys_commitment,
                 psbt_clear_input_inflation_keys_commitment, dummy_commitment, dummy_txid),
                # PSET: blinded inflation keys rangeproof
                (psbt_set_input_inflation_keys_rangeproof, psbt_get_input_inflation_keys_rangeproof,
                 psbt_clear_input_inflation_keys_rangeproof, dummy_bytes, None),
                # PSET: blidned inflation keys value rangeproof
                #       (Confusing: this proves the number of blinded reissuance tokens
                #        matches the unblinded number, for constructors/blinders use)
                (psbt_set_input_inflation_keys_blinding_rangeproof,
                 psbt_get_input_inflation_keys_blinding_rangeproof,
                 psbt_clear_input_inflation_keys_blinding_rangeproof, dummy_bytes, None),
                # PSET: utxo rangeproof
                (psbt_set_input_utxo_rangeproof, psbt_get_input_utxo_rangeproof,
                 psbt_clear_input_utxo_rangeproof, dummy_bytes, None),
            ]
            for setfn, getfn, clearfn, valid_value, invalid_value in cases:
                self._throws(setfn, psbt, 0, valid_value)       # Non v2 PSBT
                if invalid_value:
                    self._throws(setfn, psbt, 0, invalid_value) # Invalid value
                self._throws(getfn, psbt, 0)                    # Non v2 PSBT
                self._throws(getfn, psbt, 0)                    # Non v2 PSBT
                self._throws(clearfn, psbt, 0)                  # Non v2 PSBT
                self._try_get_set_b(setfn, getfn, clearfn, pset2, valid_value)

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
                                p, dummy_unknowns, dummy_unknown_key)

        #
        # Outputs: PSBT V2
        #
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
                            psbt_get_output_amount, psbt2, 1234, mandatory=True)

        # V2: Script
        self._throws(psbt_set_output_script, psbt, 0, dummy_bytes) # Non v2 PSBT
        self._throws(psbt_get_output_script, psbt, 0)              # Non v2 PSBT
        self._throws(psbt_get_output_script_len, psbt, 0)          # Non v2 PSBT
        self._try_get_set_b(psbt_set_output_script,
                            psbt_get_output_script,
                            psbt_get_output_script_len, psbt2, dummy_bytes, mandatory=True)

        #
        # Outputs: PSET
        #
        if is_elements_build():
            # PSET: Blinder index
            for setfn, getfn in [
                (psbt_set_output_blinder_index, psbt_get_output_blinder_index)]:
                self._throws(setfn, psbt, 0, 1234) # Non v2 PSBT
                self._throws(getfn, psbt, 0)       # Non v2 PSBT
                self._try_get_set_i(setfn, None, getfn, pset2, 1234)

            cases = [
                # PSET: blinded issuance amount (issuance amount commitment)
                (psbt_set_output_value_commitment, psbt_get_output_value_commitment,
                 psbt_clear_output_value_commitment, dummy_commitment, dummy_txid),
                (psbt_set_output_asset, psbt_get_output_asset,
                 psbt_clear_output_asset, dummy_asset, dummy_commitment),
                (psbt_set_output_asset_commitment, psbt_get_output_asset_commitment,
                 psbt_clear_output_asset_commitment, dummy_commitment, dummy_txid),
                (psbt_set_output_value_rangeproof, psbt_get_output_value_rangeproof,
                 psbt_clear_output_value_rangeproof, dummy_bytes, None),
                (psbt_set_output_asset_surjectionproof,
                 psbt_get_output_asset_surjectionproof,
                 psbt_clear_output_asset_surjectionproof, dummy_bytes, None),
                (psbt_set_output_blinding_public_key, psbt_get_output_blinding_public_key,
                 psbt_clear_output_blinding_public_key, dummy_pubkey, dummy_sig),
                (psbt_set_output_ecdh_public_key, psbt_get_output_ecdh_public_key,
                 psbt_clear_output_ecdh_public_key, dummy_pubkey, dummy_sig),
                (psbt_set_output_value_blinding_rangeproof,
                 psbt_get_output_value_blinding_rangeproof,
                 psbt_clear_output_value_blinding_rangeproof, dummy_bytes, None),
                (psbt_set_output_asset_blinding_surjectionproof,
                 psbt_get_output_asset_blinding_surjectionproof,
                 psbt_clear_output_asset_blinding_surjectionproof, dummy_bytes, None),
            ]
            for setfn, getfn, clearfn, valid_value, invalid_value in cases:
                self._throws(setfn, psbt, 0, valid_value)       # Non v2 PSBT
                if invalid_value:
                    self._throws(setfn, psbt, 0, invalid_value) # Invalid value
                self._throws(getfn, psbt, 0)                    # Non v2 PSBT
                self._throws(getfn, psbt, 0)                    # Non v2 PSBT
                self._throws(clearfn, psbt, 0)                  # Non v2 PSBT
                is_commitment_fn = setfn in [psbt_set_output_value_commitment,
                                             psbt_set_output_asset_commitment,
                                             psbt_set_output_value_blinding_rangeproof,
                                             psbt_set_output_asset_blinding_surjectionproof]
                self._try_get_set_b(setfn, getfn, clearfn, pset2, valid_value,
                                    roundtrip=not is_commitment_fn)
                if is_commitment_fn:
                    clearfn(pset2, 0)
                else:
                    self._round_trip(pset2)

if __name__ == '__main__':
    unittest.main()
