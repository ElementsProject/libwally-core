"""Tests for transaction construction"""
import unittest
from wallycore import *

FLAG_USE_WITNESS =  0x1
FLAG_USE_ELEMENTS = 0x2

class ElementsTxTests(unittest.TestCase):

    def test_tx_input(self):
        # Test invalid inputs
        txhash, seq, script, witness_script = b'0' * 32, 0xffffffff, b'0000', b'000000'
        nonce, entropy = b'0' * 32, b'0' * 32
        witness = tx_witness_stack_init(5)
        tx_witness_stack_add(witness, witness_script)
        with self.assertRaises(TypeError):
            tx_elements_input_init(None, 0, seq, script, witness, nonce, entropy, None, None, None, None) # Null txhash
        with self.assertRaises(ValueError):
            tx_elements_input_init(bytes(), 0, seq, script, witness, nonce, entropy, None, None, None, None) # Empty txhash

        # Create a valid input
        tx_input = tx_elements_input_init(txhash, 0, seq, script, witness, nonce, entropy, None, None, None, None)
        self.assertEqual(tx_input_get_txhash(tx_input), txhash)
        self.assertEqual(tx_input_get_index(tx_input), 0)
        self.assertEqual(tx_input_get_sequence(tx_input), seq)
        self.assertEqual(tx_input_get_script_len(tx_input), len(script))
        self.assertEqual(tx_input_get_script(tx_input), script)
        self.assertEqual(tx_input_get_witness_len(tx_input, 0), len(witness_script))
        self.assertEqual(tx_input_get_witness(tx_input, 0), witness_script)
        # Witness can be null
        tx_input = tx_elements_input_init(txhash, 0, seq, b'0000', None, None, None, None, None, None, None)
        with self.assertRaises(ValueError):
            tx_input_get_witness(tx_input, 0) # Can't get a non-existent witness

    def test_tx_output(self):
        # Test invalid outputs
        satoshi, script = 10000, b'0000'

        # Create a valid output
        ct_value = tx_confidential_value_from_satoshi(satoshi)
        tx_output = tx_elements_output_init(script, None, ct_value, None, None, None)
        self.assertEqual(tx_output_get_script_len(tx_output), len(script))
        self.assertEqual(tx_output_get_script(tx_output), script)

    def test_tx(self):
        txhash, seq, script, witness_script = b'0' * 32, 0xffffffff, b'0000', b'000000'
        nonce, entropy = b'0' * 32, b'0' * 32
        witness = tx_witness_stack_init(5)
        tx_witness_stack_add(witness, witness_script)
        tx_input = tx_elements_input_init(txhash, 0, seq, script, witness, nonce, entropy, None, None, None, None)
        tx_input_no_witness = tx_elements_input_init(txhash, 0, seq, script, None, nonce, entropy, None, None, None, None)

        ct_value = tx_confidential_value_from_satoshi(10000)
        tx_output = tx_elements_output_init(script, None, ct_value, None, None, None)

        tx = tx_init(2, 0, 10, 2)
        self.assertEqual(tx_get_num_inputs(tx), 0)
        self.assertEqual(tx_get_witness_count(tx), 0)
        self.assertEqual(tx_get_num_outputs(tx), 0)
        self.assertEqual(tx_get_total_output_satoshi(tx), 0)
        tx_add_input(tx, tx_input_no_witness)
        self.assertEqual(tx_get_num_inputs(tx), 1)
        self.assertEqual(tx_get_witness_count(tx), 0)
        tx_add_input(tx, tx_input)
        self.assertEqual(tx_get_witness_count(tx), 1)
        tx_add_input(tx, tx_input)
        tx_add_elements_raw_input(tx, txhash, 0, seq, script, witness, nonce, entropy, None, None, None, None, 0)
        with self.assertRaises(ValueError):
            tx_remove_input(tx, 4)
        tx_remove_input(tx, 2) # Remove last
        tx_remove_input(tx, 1) # Remove middle
        tx_remove_input(tx, 0) # Remove first
        tx_remove_input(tx, 0) # Remove only input

        tx_add_input(tx, tx_input)
        tx_add_output(tx, tx_output)
        ct_value = tx_confidential_value_from_satoshi(20000)
        tx_add_elements_raw_output(tx, script, None, ct_value, None, None, None, 0)
        size = tx_get_length(tx, 0)
        vsize = tx_vsize_from_weight(tx_get_weight(tx))
        tx_hex = tx_to_hex(tx, FLAG_USE_WITNESS|FLAG_USE_ELEMENTS)

    def test_issuance(self):
        txhash = hex_to_bytes("39453cf897e2f0c2e9563364874f4b2a85be06dd8ec10665085033eeb75016c3")[::-1]
        vout = 68
        contract_hash = bytearray(b'\x00'*32)
        entropy = tx_elements_issuance_generate_entropy(txhash, vout, contract_hash)
        self.assertEqual(hex_from_bytes(entropy), "3db9d8b4a9da087b42f29f34431412aaa24d63750bb31b9a2e263797248135e0")
        asset = tx_elements_issuance_calculate_asset(entropy)
        self.assertEqual(hex_from_bytes(asset[::-1]), "dedf795f74e8b52c6ff8a9ad390850a87b18aeb2be9d1967038308290093a893")

if __name__ == '__main__':
    unittest.main()
