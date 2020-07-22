"""Tests for PSBT wrappers"""
import unittest
from wallycore import *

SAMPLE = "cHNidP8BAFICAAAAAZ38ZijCbFiZ/hvT3DOGZb/VXXraEPYiCXPfLTht7BJ2AQAAAAD/////AfA9zR0AAAAAFgAUezoAv9wU0neVwrdJAdCdpu8TNXkAAAAATwEENYfPAto/0AiAAAAAlwSLGtBEWx7IJ1UXcnyHtOTrwYogP/oPlMAVZr046QADUbdDiH7h1A3DKmBDck8tZFmztaTXPa7I+64EcvO8Q+IM2QxqT64AAIAAAACATwEENYfPAto/0AiAAAABuQRSQnE5zXjCz/JES+NTzVhgXj5RMoXlKLQH+uP2FzUD0wpel8itvFV9rCrZp+OcFyLrrGnmaLbyZnzB1nHIPKsM2QxqT64AAIABAACAAAEBKwBlzR0AAAAAIgAgLFSGEmxJeAeagU4TcV1l82RZ5NbMre0mbQUIZFuvpjIBBUdSIQKdoSzbWyNWkrkVNq/v5ckcOrlHPY5DtTODarRWKZyIcSEDNys0I07Xz5wf6l0F1EFVeSe+lUKxYusC4ass6AIkwAtSriIGAp2hLNtbI1aSuRU2r+/lyRw6uUc9jkO1M4NqtFYpnIhxENkMak+uAACAAAAAgAAAAAAiBgM3KzQjTtfPnB/qXQXUQVV5J76VQrFi6wLhqyzoAiTACxDZDGpPrgAAgAEAAIAAAAAAACICA57/H1R6HV+S36K6evaslxpL0DukpzSwMVaiVritOh75EO3kXMUAAACAAAAAgAEAAIAA"


class PSBTTests(unittest.TestCase):

    def _try_set(self, fn, psbt, valid_value, null_value=None):
        fn(psbt, 0, valid_value) # Set
        fn(psbt, 0, null_value) # Un-set
        with self.assertRaises(ValueError):
            fn(None, 0, valid_value) # Null PSBT
        with self.assertRaises(ValueError):
            fn(psbt, 1, valid_value) # Invalid index


    def test_psbt(self):
        psbt = psbt_from_base64(SAMPLE)

        self.assertIsNotNone(psbt_get_global_tx(psbt))

        self.assertEqual(psbt_get_version(psbt), 0)
        self.assertEqual(psbt_get_num_inputs(psbt), 1)
        self.assertEqual(psbt_get_num_outputs(psbt), 1)

        # Conversion to base64 should round trip
        self.assertEqual(psbt_to_base64(psbt, 0), SAMPLE)

        # Combining with ourselves shouldn't change the PSBT
        psbt_combine(psbt, psbt)
        self.assertEqual(psbt_to_base64(psbt, 0), SAMPLE)

        # Test setters
        dummy_tx = psbt_get_global_tx(psbt)
        self.assertIsNotNone(dummy_tx)

        dummy_txout = tx_output_init(1234567, bytearray(b'\x00' * 33))

        dummy_witness = tx_witness_stack_init(5)
        self.assertIsNotNone(dummy_witness)

        dummy_bytes = bytearray(b'\x00' * 32)
        dummy_pubkey = bytearray(b'\x02'* EC_PUBLIC_KEY_LEN)
        dummy_fingerprint = bytearray(b'\x00' * BIP32_KEY_FINGERPRINT_LEN)
        dummy_path = [1234, 1234, 1234]
        dummy_sig = bytearray(b'\x00' * 72)
        if is_elements_build():
            dummy_nonce = bytearray(b'\x00' * WALLY_TX_ASSET_CT_NONCE_LEN)
            dummy_bf = bytearray(b'\x00' * BLINDING_FACTOR_LEN)
            dummy_commitment = bytearray(b'\x00' * ASSET_COMMITMENT_LEN)

        dummy_keypaths = keypath_map_init(0)
        self.assertIsNotNone(dummy_keypaths)
        keypath_map_add(dummy_keypaths, dummy_pubkey, dummy_fingerprint, dummy_path)
        self.assertEqual(keypath_map_find(dummy_keypaths, dummy_pubkey), 1)

        dummy_partial_sigs = partial_sigs_map_init(0)
        self.assertIsNotNone(dummy_partial_sigs)
        partial_sigs_map_add(dummy_partial_sigs, dummy_pubkey, dummy_sig)
        self.assertEqual(partial_sigs_map_find(dummy_partial_sigs, dummy_pubkey), 1)

        dummy_unknowns = unknowns_map_init(1)
        self.assertIsNotNone(dummy_unknowns)
        unknowns_map_add(dummy_unknowns, dummy_pubkey, dummy_fingerprint)
        self.assertEqual(unknowns_map_find(dummy_unknowns, dummy_pubkey), 1)

        #
        # Inputs
        #
        self._try_set(psbt_set_input_non_witness_utxo, psbt, dummy_tx)
        self._try_set(psbt_set_input_witness_utxo, psbt, dummy_txout)
        self._try_set(psbt_set_input_final_witness, psbt, dummy_witness)
        self._try_set(psbt_set_input_keypaths, psbt, dummy_keypaths)
        self._try_set(psbt_set_input_partial_sigs, psbt, dummy_partial_sigs)
        self._try_set(psbt_set_input_unknowns, psbt, dummy_unknowns)
        self._try_set(psbt_set_input_sighash_type, psbt, 0xff, 0x0)
        self._try_set(psbt_set_input_redeem_script, psbt, dummy_bytes)
        self._try_set(psbt_set_input_witness_script, psbt, dummy_bytes)
        self._try_set(psbt_set_input_final_script_sig, psbt, dummy_bytes)

        #
        # Outputs
        #
        self._try_set(psbt_set_output_redeem_script, psbt, dummy_bytes)
        self._try_set(psbt_set_output_witness_script, psbt, dummy_bytes)
        self._try_set(psbt_set_output_keypaths, psbt, dummy_keypaths)
        self._try_set(psbt_set_output_unknowns, psbt, dummy_unknowns)
        if is_elements_build():
            self._try_set(psbt_set_output_blinding_pubkey, psbt, dummy_pubkey)
            self._try_set(psbt_set_output_value_commitment, psbt, dummy_commitment)
            self._try_set(psbt_set_output_vbf, psbt, dummy_bf)
            self._try_set(psbt_set_output_asset_commitment, psbt, dummy_commitment)
            self._try_set(psbt_set_output_abf, psbt, dummy_bf)
            self._try_set(psbt_set_output_nonce, psbt, dummy_nonce)
            self._try_set(psbt_set_output_rangeproof, psbt, dummy_bytes)
            self._try_set(psbt_set_output_surjectionproof, psbt, dummy_bytes)


if __name__ == '__main__':
    unittest.main()
