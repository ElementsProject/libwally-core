import json
import unittest
from util import *

MAX_SATOSHI = 21000000 * 100000000

TX_MAX_LEN = 1000
TX_MAX_VERSION = 2

TX_FAKE_HEX = utf8('010000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000')
TX_HEX = utf8('0100000001be66e10da854e7aea9338c1f91cd489768d1d6d7189f586d7a3613f2a24d5396000000008b483045022100da43201760bda697222002f56266bf65023fef2094519e13077f777baed553b102205ce35d05eabda58cd50a67977a65706347cc25ef43153e309ff210a134722e9e0141042daa93315eebbe2cb9b5c3505df4c6fb6caca8b756786098567550d4820c09db988fe9997d049d687292f815ccd6e7fb5c1b1a91137999818d17c73d0f80aef9ffffffff0123ce0100000000001976a9142bc89c2702e0e618db7d59eb5ce2f0f147b4075488ac00000000')
TX_WITNESS_HEX = utf8('020000000001012f94ddd965758445be2dfac132c5e75c517edf5ea04b745a953d0bc04c32829901000000006aedc98002a8c500000000000022002009246bbe3beb48cf1f6f2954f90d648eb04d68570b797e104fead9e6c3c87fd40544020000000000160014c221cdfc1b867d82f19d761d4e09f3b6216d8a8304004830450221008aaa56e4f0efa1f7b7ed690944ac1b59f046a59306fcd1d09924936bd500046d02202b22e13a2ad7e16a0390d726c56dfc9f07647f7abcfac651e35e5dc9d830fc8a01483045022100e096ad0acdc9e8261d1cdad973f7f234ee84a6ee68e0b89ff0c1370896e63fe102202ec36d7554d1feac8bc297279f89830da98953664b73d38767e81ee0763b9988014752210390134e68561872313ba59e56700732483f4a43c2de24559cb8c7039f25f7faf821039eb59b267a78f1020f27a83dc5e3b1e4157e4a517774040a196e9f43f08ad17d52ae89a3b720')

# Test vectors from:
# https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json
with open(root_dir + 'src/data/bip341_vectors.json', 'r') as f:
    JSON = json.load(f)


class TransactionTests(unittest.TestCase):

    def tx_deserialize_hex(self, hex_):
        tx_p = pointer(wally_tx())
        self.assertEqual(WALLY_OK, wally_tx_from_hex(hex_, 0x0, tx_p))
        return tx_p[0]

    def tx_serialize_hex(self, tx):
        ret, hex_ = wally_tx_to_hex(tx, 0x1)
        self.assertEqual(ret, WALLY_OK)
        return hex_

    def test_serialization(self):
        """Testing serialization and deserialization"""
        tx_out = pointer(wally_tx())
        tx_copy = pointer(wally_tx())

        # Invalid arguments
        for args in [
            (None, 0, tx_out), # Null hex
            (utf8(''), 0, tx_out), # Empty hex
            (utf8('00'*5), 0, tx_out), # Short hex
            (TX_FAKE_HEX, 0, None), # Empty output
            (TX_FAKE_HEX, 16, tx_out), # Unsupported flag
            (TX_WITNESS_HEX[:11]+utf8('0')+TX_WITNESS_HEX[12:], 0, tx_out), # Invalid witness flag
            ]:
            self.assertEqual(WALLY_EINVAL, wally_tx_from_hex(*args))

        # No-input/no-output transactions
        for tx_hex in [
             TX_FAKE_HEX[:9]+utf8('0')+TX_FAKE_HEX[92:],   # No inputs
             TX_FAKE_HEX[:93]+utf8('0')+TX_FAKE_HEX[112:], # No outputs
            ]:
            self.assertEqual(WALLY_OK, wally_tx_from_hex(tx_hex, 0, tx_out))
            # Partial transactions cannot be dumped by default
            self.assertEqual(WALLY_EINVAL, wally_tx_to_hex(tx_out, 0)[0])
            # Check the partial transaction can be cloned
            self.assertEqual(WALLY_OK, wally_tx_clone_alloc(tx_out, 0, tx_copy))
            if tx_out.contents.num_inputs != 0:
                # Partial txs with inputs can be dumped with ALLOW_PARTIAL:0x4
                ret, hex_ = wally_tx_to_hex(tx_out, 0x1|0x4)
                self.assertEqual(WALLY_OK, ret)
                self.assertEqual(tx_hex, utf8(hex_))

        # Valid transactions
        for tx_hex in [ TX_HEX,
                        utf8('00')+TX_HEX[2:],
                        utf8('ff')+TX_FAKE_HEX[2:],
                        TX_FAKE_HEX,
                        TX_WITNESS_HEX ]:
            self.assertEqual(WALLY_OK, wally_tx_from_hex(tx_hex, 0 ,tx_out))
            hex_ = utf8(self.tx_serialize_hex(tx_out))
            self.assertEqual(tx_hex, hex_)
            # Check the transaction can be cloned and serializes to the same hex
            self.assertEqual(WALLY_OK, wally_tx_clone_alloc(tx_out, 0, tx_copy))
            self.assertEqual(hex_, utf8(self.tx_serialize_hex(tx_copy)))
            # Check that the txid can be computed
            txid, txid_len = make_cbuffer('00' * 32)
            self.assertEqual(WALLY_OK, wally_tx_get_txid(tx_out, txid, txid_len))
            # Check the transaction can be cloned without finalization data
            tx_nf, flag_nf = pointer(wally_tx()), 0x1
            self.assertEqual(WALLY_OK, wally_tx_clone_alloc(tx_out, flag_nf, tx_nf))
            for i in range(tx_copy.contents.num_inputs):
                wally_tx_set_input_script(tx_copy, i, None, 0)
                wally_tx_set_input_witness(tx_copy, i, None)
            self.assertEqual(utf8(self.tx_serialize_hex(tx_copy)),
                             utf8(self.tx_serialize_hex(tx_nf)))

    def test_lengths(self):
        """Testing functions measuring different lengths for a tx"""
        for tx_hex, length in [
            (TX_FAKE_HEX, 60),
            (TX_HEX, 224),
            (TX_WITNESS_HEX, 125),
            ]:
            tx = self.tx_deserialize_hex(tx_hex)
            length_with_witness = len(tx_hex) // 2
            witness_len = length_with_witness - length
            weight = witness_len + length * 4
            vsize = (weight + 3) // 4
            self.assertEqual((WALLY_OK, length), wally_tx_get_length(byref(tx), 0))
            self.assertEqual((WALLY_OK, length_with_witness), wally_tx_get_length(byref(tx), 1))
            self.assertEqual((WALLY_EINVAL, 0), wally_tx_get_length(byref(tx), 16)) # Unsupported flag
            self.assertEqual((WALLY_OK, weight), wally_tx_get_weight(byref(tx)))
            self.assertEqual((WALLY_OK, vsize), wally_tx_get_vsize(byref(tx)))
            self.assertEqual((WALLY_OK, vsize), wally_tx_vsize_from_weight(weight))
            if witness_len > 0:
                ret, count = wally_tx_get_witness_count(byref(tx))
                self.assertEqual(WALLY_OK, ret)
                self.assertTrue(count > 0)

    def test_outputs(self):
        """Testing functions manipulating outputs"""
        # Add
        script, script_len = make_cbuffer('00')
        for args in [
            (None, 1, script, script_len, 0), # Invalid tx
            (wally_tx(), -1, script, script_len, 0), # Invalid amount
            (wally_tx(), MAX_SATOSHI+1, script, script_len, 0), # Invalid amount
            (self.tx_deserialize_hex(TX_HEX), MAX_SATOSHI, script, script_len, 0), # Invalid total amount
            (wally_tx(), 1, None, script_len, 0), # Empty script
            (wally_tx(), 1, script, 0, 0), # Invalid script length
            (wally_tx(), 1, script, script_len, 1), # Invalid flag
            ]:
            self.assertEqual(WALLY_EINVAL, wally_tx_add_raw_output(*args))
            # Testing only wally_tx_add_raw_output, because it calls wally_tx_add_output and
            # wally_tx_get_total_output_satoshi

        # Remove
        for args in [
            (None, 0), # Invalid tx
            (wally_tx(), 0), # Remove from empty tx
            (self.tx_deserialize_hex(TX_FAKE_HEX), 1), # Invalid index
            ]:
            self.assertEqual(WALLY_EINVAL, wally_tx_remove_output(*args))

        # Add and remove inputs and outputs, test that serialization remains the same
        script2, script2_len = make_cbuffer('77' * 16)
        tx = self.tx_deserialize_hex(TX_FAKE_HEX)
        self.assertEqual(WALLY_OK, wally_tx_add_raw_output(tx, 55, script2, script2_len, 0))
        before_hex = self.tx_serialize_hex(tx)
        num_outputs = tx.num_outputs

        def remove_and_test(idx):
            self.assertNotEqual(before_hex, self.tx_serialize_hex(tx))
            self.assertEqual(WALLY_OK, wally_tx_remove_output(tx, idx))
            self.assertEqual(before_hex, self.tx_serialize_hex(tx))

        self.assertEqual(WALLY_OK, wally_tx_add_raw_output(tx, 1, script, script_len, 0))
        remove_and_test(num_outputs)
        for idx in range(0, num_outputs + 1):
            ret = wally_tx_add_raw_output_at(tx, idx, 1, script, script_len, 0)
            self.assertEqual(ret, WALLY_OK)
            remove_and_test(idx)

        ret = wally_tx_add_raw_output_at(tx, num_outputs + 1, 1, script, script_len, 0)
        self.assertEqual(ret, WALLY_EINVAL) # Invalid index

    def test_inputs(self):
        """Testing functions manipulating inputs"""
        # Add
        txhash, txhash_len = make_cbuffer('00'*32)
        script, script_len = make_cbuffer('00')
        for args in [
            (None, txhash, txhash_len, 0, 0xffffffff, script, script_len, None, 0), # Empty tx
            (wally_tx(), None, txhash_len, 0, 0xffffffff, script, script_len, None, 0), # Empty hash
            (wally_tx(), txhash, txhash_len-1, 0, 0xffffffff, script, script_len, None, 0), # Invalid hash length
            (wally_tx(), txhash, txhash_len, 0, 0xffffffff, None, script_len, None, 0), # Empty script
            (wally_tx(), txhash, txhash_len, 0, 0xffffffff, script, 0, None, 0), # Invalid script length
            (wally_tx(), txhash, txhash_len, 0, 0xffffffff, script, script_len, None, 1), # Unsupported flags
            ]:
            self.assertEqual(WALLY_EINVAL, wally_tx_add_raw_input(*args))
            # Testing only wally_tx_add_raw_input, because it calls wally_tx_add_input

        # Remove
        for args in [
            (None, 0), # Invalid tx
            (wally_tx(), 0), # Remove from empty tx
            (self.tx_deserialize_hex(TX_FAKE_HEX), 1), # Invalid index
            ]:
            self.assertEqual(WALLY_EINVAL, wally_tx_remove_input(*args))

        # Add and then remove, then test that serialization remains the same
        wit = wally_tx_witness_stack()
        for args, expected in [
            ((self.tx_deserialize_hex(TX_FAKE_HEX), txhash, txhash_len, 0, 0xffffffff, script, script_len, wit, 0),
             None),
            ((self.tx_deserialize_hex(TX_WITNESS_HEX), txhash, txhash_len, 0, 0xffffffff, script, script_len, wit, 0),
             TX_WITNESS_HEX[:13]+utf8('2')+TX_WITNESS_HEX[14:96]+utf8('00'*36)+utf8('0100ffffffff')+TX_WITNESS_HEX[96:-8]+utf8('00')+TX_WITNESS_HEX[-8:]),
            ]:
            before = self.tx_serialize_hex(args[0])
            self.assertEqual(WALLY_OK, wally_tx_add_raw_input(*args))
            if expected:
                self.assertEqual(utf8(self.tx_serialize_hex(args[0])), expected)
            self.assertEqual(WALLY_OK, wally_tx_remove_input(byref(args[0]), args[0].num_inputs-1))
            self.assertEqual(before, self.tx_serialize_hex(args[0]))

        script2, script2_len = make_cbuffer('77' * 16)
        tx = self.tx_deserialize_hex(TX_FAKE_HEX)
        ret = wally_tx_add_raw_input(tx, txhash, txhash_len, 1, 0xfffffffe, script2, script2_len, wit, 0)
        self.assertEqual(ret, WALLY_OK)
        before_hex = self.tx_serialize_hex(tx)
        num_inputs = tx.num_inputs

        def remove_and_test(idx):
            self.assertNotEqual(before_hex, self.tx_serialize_hex(tx))
            self.assertEqual(WALLY_OK, wally_tx_remove_input(tx, idx))
            self.assertEqual(before_hex, self.tx_serialize_hex(tx))

        for idx in range(0, num_inputs + 1):
            ret = wally_tx_add_raw_input_at(tx, idx, txhash, txhash_len,
                                            2, 0xfffffffd, script, script_len, wit, 0)
            self.assertEqual(ret, WALLY_OK)
            remove_and_test(idx)

        ret = wally_tx_add_raw_input_at(tx, num_inputs + 1, txhash, txhash_len,
                                        2, 0xfffffffd, script, script_len, wit, 0)
        self.assertEqual(ret, WALLY_EINVAL) # Invalid index


    def test_witness(self):
        """Testing functions manipulating witness stacks"""
        witness = wally_tx_witness_stack()
        item, item_len = make_cbuffer('00')
        out, out_len = make_cbuffer('00'*128)

        for args in [
            (None,    item, item_len), # NULL stack
            (witness, None, item_len), # NULL stack item
            ]:
            self.assertEqual(WALLY_EINVAL, wally_tx_witness_stack_add(*args))
            # Testing only wally_tx_witness_stack_add, because it calls wally_tx_witness_stack_set

        for fn in [wally_tx_witness_stack_get_num_items, wally_tx_witness_stack_get_length]:
            self.assertEqual((WALLY_EINVAL, 0), fn(None)) # NULL stack
        # An empty stack has no items and is serialized as a single 0x00 byte
        self.assertEqual((WALLY_OK, 0), wally_tx_witness_stack_get_num_items(witness))
        self.assertEqual((WALLY_OK, 1), wally_tx_witness_stack_get_length(witness))

        for args in [
            (witness, None, 0),        # Empty stack items are allowed
            (witness, item, 0),        # Zero-length stack items are allowed
            (witness, item, item_len), # Add a single byte item
            ]:
            self.assertEqual(WALLY_OK, wally_tx_witness_stack_add(*args))

        # Witness stack now contains 3 items (2 empty, 1 single byte)
        self.assertEqual((WALLY_OK, 3), wally_tx_witness_stack_get_num_items(witness))
        # 03 (num_items) 00 (0-length item) 00 (0-length item) 0100 (1-length zero byte item)
        expected, expected_len = make_cbuffer('0300000100')
        self.assertEqual((WALLY_OK, expected_len), wally_tx_witness_stack_get_length(witness))

        for args in [
            (None,    out,  out_len),      # NULL stack
            (witness, None, out_len),      # NULL output
            (witness, None, expected_len), # output too small
            ]:
            self.assertEqual((WALLY_EINVAL, 0), wally_tx_witness_stack_to_bytes(*args))

        # Round-trip serialization
        def check_witness_to_bytes(w, expected, expected_len):
            out, out_len = make_cbuffer('00' * 64)
            ret, written = wally_tx_witness_stack_to_bytes(w, out, out_len)
            self.assertEqual((ret, written), (WALLY_OK, expected_len))
            self.assertEqual(h(out[:written]), utf8(expected[:expected_len * 2]))
        def witness_roundtrip(src, expected_len, num_items):
            w = pointer(wally_tx_witness_stack())
            b, b_len = make_cbuffer(src)
            ret = wally_tx_witness_stack_from_bytes(b, b_len, w)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual((WALLY_OK, num_items), wally_tx_witness_stack_get_num_items(w))
            check_witness_to_bytes(w, src, expected_len)

        for src, expected_len, num_items in [
            ('00',           1, 0),
            ('0100',         2, 1),
            ('0300000100',   5, 3),
            ('030000010000', 5, 3), # Note trailing bytes are ignored
            ]:
            witness_roundtrip(src, expected_len, num_items)

    def test_get_signature_hash(self):
        """Testing function to get the signature hash"""
        tx = self.tx_deserialize_hex(TX_FAKE_HEX)
        script, script_len = make_cbuffer('00')
        out, out_len = make_cbuffer('00'*32)
        for args in [
            (None, 0, script, script_len, 1, 1, 0, out, out_len), # Empty tx
            (tx, 0, None, script_len, 1, 1, 0, out, out_len), # Empty script
            (tx, 0, script, 0, 1, 1, 0, out, out_len), # Invalid script length
            (tx, 0, script, script_len, MAX_SATOSHI+1, 1, 1, out, out_len), # Invalid amount (only with segwit)
            (tx, 0, script, script_len, 1, 0x100, 0, out, out_len), # Invalid sighash
            (tx, 0, script, script_len, 1, 1, 16, out, out_len), # Invalid flags
            (tx, 0, script, script_len, 1, 1, 0, None, out_len), # Empty bytes
            (tx, 0, script, script_len, 1, 1, 0, out, 31), # Short len
            ]:
            self.assertEqual(WALLY_EINVAL, wally_tx_get_btc_signature_hash(*args))

        def sha256d(hex_):
            bin_input, bin_input_len = make_cbuffer(hex_)
            buf, buf_len = make_cbuffer('00'*32)
            self.assertEqual(WALLY_OK, wally_sha256d(bin_input, bin_input_len, buf, buf_len))
            return h(buf)

        script, script_len = make_cbuffer('00')
        out, out_len = make_cbuffer('00'*32)
        for args, expected in [
            ((tx, 0, script, script_len, 1, 1, 0, out, out_len),
             utf8('1bcf681d585c3cbbc64b30a69e60b721fc0aacc57132dfbe43af6df8f4797a80')),
           ((tx, 1, script, script_len, 1, 1, 0, out, out_len),
            utf8('01'+'00'*31)),
           ((tx, 0, script, script_len, 1, 0, 0, out, out_len),
            utf8('882630e74173c928fc18236b99e25ffd15643faabc65c010e9ca27b8db29278a')),
           ((tx, 0, script, script_len, 1, 1, 1, out, out_len),
            utf8('5dad88b42332e3559950b325bba69eedb64b9330e55585fc1098964572f9c45d')),
           ((tx, 0, script, script_len, 0, 1, 1, out, out_len),
            utf8('bb30f5feed35b2591eedd8e778d507236a756e8c2eff8cf72ef0afa83abdea31')),
            ]:
            self.assertEqual(WALLY_OK, wally_tx_get_btc_signature_hash(*args))
            self.assertEqual(expected, h(out[:out_len]))

    def test_hash_prevouts(self):
        """Test functions computing hash_prevouts"""
        if not wally_is_elements_build()[1]:
            # The direct access tx.num_inputs/tx.inputs[i].txhash/tx.inputs[i].index
            # below only works if this is an elements build. Skip this test for
            # non-elements builds until the tx accessors are available to call
            # when SWIG is not defined.
            self.skipTest('https://github.com/ElementsProject/libwally-core/issues/388')

        out, out_len = make_cbuffer('00'*32)
        # The first sample tx from BIP-0143
        bip143_tx = '0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000'
        for tx_hex, expected in [
            # Note this test case must be last for the invalid tests below
            (bip143_tx, utf8('96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37'))
            ]:
            # Compute from the tx
            tx = self.tx_deserialize_hex(tx_hex)
            # Can be called with 'all inputs marker' 0xffffffff or the actual num_inputs
            for start, count in [(0, 0xffffffff), (0, tx.num_inputs)]:
                ret = wally_tx_get_hash_prevouts(tx, start, count, out, out_len)
                self.assertEqual(ret, WALLY_OK)
                self.assertEqual(h(out[:out_len]), expected)
            # Can be called with a subset of inputs (although we have no vectors for this)
            ret = wally_tx_get_hash_prevouts(tx, 0, 1, out, out_len) # Just the first input
            self.assertEqual(ret, WALLY_OK)
            self.assertNotEqual(h(out[:out_len]), expected)

            # Compute from the underlying data
            txhashes, indices = bytearray(), (c_uint * tx.num_inputs)()
            for i in range(tx.num_inputs):
                txhashes.extend(tx.inputs[i].txhash)
                indices[i] = tx.inputs[i].index
            txhashes = bytes(txhashes)
            ret = wally_get_hash_prevouts(txhashes, len(txhashes),
                                          indices, len(indices), out, out_len)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(h(out[:out_len]), expected)

        # Invalid args
        cases = [
            (None, 0, 0xffffffff, out,  out_len),     # NULL tx
            (tx,   2, 1,          out,  out_len),     # Start index >= num tx inputs
            (tx,   1, 0xffffffff, out,  out_len),     # Non-zero start index + all inputs marker
            (tx,   1, 2,          out,  out_len),     # Start index + num_inputs > num tx inputs
            (tx,   0, 0,          out,  out_len),     # Zero num_inputs
            (tx,   0, 3,          out,  out_len),     # num_inputs > num tx inputs
            (tx,   0, 0xffffffff, None, out_len),     # Null output
            (tx,   0, 0xffffffff, out,  out_len - 1), # Invalid output length
        ]
        for args in cases:
            self.assertEqual(WALLY_EINVAL, wally_tx_get_hash_prevouts(*args))

        cases = [
            (None,     len(txhashes), indices, len(indices), out,  out_len), # NULL txhashes
            (txhashes, 0,             indices, len(indices), out,  out_len), # Zero hash len
            (txhashes, 16,            indices, len(indices), out,  out_len), # Incorect hash len
            (txhashes, len(txhashes), None,    len(indices), out,  out_len), # NULL indices
            (txhashes, len(txhashes), indices, 0,            out,  out_len), # Zero num indices
            (txhashes, len(txhashes), indices, 1,            out,  out_len), # Num indices != num hashes
            (txhashes, len(txhashes), indices, len(indices), None, out_len), # NULL output
            (txhashes, len(txhashes), indices, len(indices), out,  out_len - 1), # Invalid output length
        ]
        for args in cases:
            self.assertEqual(WALLY_EINVAL, wally_get_hash_prevouts(*args))

    def test_bip341_tweak(self):
        """Tests for computing the bip341 signature hash"""

        pubkey_cases = []
        mc = lambda h: (None, 0) if h is None else make_cbuffer(h)
        for i in range(len(JSON['scriptPubKey'])):
            case = JSON['scriptPubKey'][i]
            inter = case['intermediary']
            pubkey_cases.append((mc(case['given']['internalPubkey']),
                mc(inter['merkleRoot']), utf8(inter['tweakedPubkey'])))

        bytes_out, out_len = make_cbuffer('00'*33)
        for case in pubkey_cases:
            ((pub_key, pub_key_len), (merkle, merkle_len), expected) = case
            args = [pub_key, pub_key_len, merkle, merkle_len, 0, bytes_out, out_len]
            ret = wally_ec_public_key_bip341_tweak(*args)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(expected, h(bytes_out[1:out_len]))

        privkey_cases = []
        mc = lambda h: (None, 0) if h is None else make_cbuffer(h)
        for i in range(len(JSON['keyPathSpending'][0]['inputSpending'])):
            case = JSON['keyPathSpending'][0]['inputSpending'][i]
            inter, given = case['intermediary'], case['given']
            privkey_cases.append((mc(given['internalPrivkey']),
                mc(given['merkleRoot']), utf8(inter['tweakedPrivkey'])))

        bytes_out, out_len = make_cbuffer('00'*32)
        for case in privkey_cases:
            ((priv_key, priv_key_len), (merkle, merkle_len), expected) = case
            args = [priv_key, priv_key_len, merkle, merkle_len, 0, bytes_out, out_len]
            ret = wally_ec_private_key_bip341_tweak(*args)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(expected, h(bytes_out[:out_len]))

        # FIXME: Add invalid arguments cases for pub/priv keys

    def test_get_taproot_signature_hash(self):
        """Tests for computing the taproot signature hash"""

        keyspend_case = JSON['keyPathSpending'][0]
        input_spending = keyspend_case['inputSpending']
        utxos = keyspend_case['given']['utxosSpent']
        num_utxos = len(utxos)

        scripts = pointer(wally_map())
        wally_map_init_alloc(num_utxos, None, scripts)
        values = (c_uint64 * num_utxos)()
        num_values = num_utxos
        # Bad/Faked data for invalid parameter checks
        empty_scripts = pointer(wally_map())
        non_tr_scripts = pointer(wally_map())
        wally_map_init_alloc(num_utxos, None, non_tr_scripts)
        fake_script, fake_script_len = make_cbuffer('00')
        fake_annex, fake_annex_len = make_cbuffer('5000')
        bad_annex, bad_annex_len = make_cbuffer('00')

        for i, utxo in enumerate(utxos):
            script, script_len = make_cbuffer(utxo['scriptPubKey'])
            wally_map_add_integer(scripts, i, script, script_len)
            wally_map_add_integer(non_tr_scripts, i, fake_script, fake_script_len)
            values[i] = int(utxo['amountSats'])

        tx = self.tx_deserialize_hex(keyspend_case['given']['rawUnsignedTx'])
        bytes_out, out_len = make_cbuffer('00'*32)

        for input_index in range(len(input_spending)):
            sighash = input_spending[input_index]['given']['hashType']
            index = input_spending[input_index]['given']['txinIndex']
            expected = utf8(input_spending[input_index]['intermediary']['sigHash'])

            # Unused in these tests
            tapleaf_script = None
            tapleaf_script_len = 0
            key_version = 0
            codesep_pos = 0xFFFFFFFF
            flags = 0
            annex = None
            annex_len = 0

            fn = wally_tx_get_btc_taproot_signature_hash
            args = [tx, index, scripts, values, num_values, tapleaf_script, tapleaf_script_len,
                    key_version, codesep_pos, annex, annex_len, sighash, flags, bytes_out, out_len]

            self.assertEqual(wally_tx_get_btc_taproot_signature_hash(*args), WALLY_OK)
            self.assertEqual(out_len, 32)
            self.assertEqual(expected, h(bytes_out[:out_len]))

        # Test that signing with a provided tapleaf script/annex works
        args[5] = fake_script
        args[6] = fake_script_len
        self.assertEqual(wally_tx_get_btc_taproot_signature_hash(*args), WALLY_OK)
        args[9] = fake_annex
        args[10] = fake_annex_len
        self.assertEqual(wally_tx_get_btc_taproot_signature_hash(*args), WALLY_OK)

        # Invalid args
        invalid_cases = [
            [(0,  None)],            # NULL tx
            [(1,  50)],              # Invalid index
            [(2,  None)],            # NULL scripts
            [(2,  empty_scripts)],   # Missing script(s)
            [(3,  None)],            # NULL values
            [(4,  0)],               # Missing values
            [(4,  1)],               # Too few values
            [(5,  fake_script)],     # Zero-length tapleaf script
            [(5,  non_tr_scripts)],  # Non-taproot input script
            [(6,  fake_script_len)], # NULL tapleaf script
            [(7,  2)],               # Invalid key version (only 0/1 are allowed)
            [(9,  fake_annex)],      # Zero length annex
            [(10, fake_annex_len)],  # NULL annex
            [(9,  bad_annex), (10, bad_annex_len)], # Missing 0x50 annex prefix
            [(11, 0xffffffff)],      # Invalid sighash
            [(12, 0x1)],             # Unknown flag(s)
            [(13, None)],            # NULL output
            [(14, 0)],               # Zero length output
            [(14, 33)],              # Incorrect length output
        ]
        for case in invalid_cases:
            args = [tx, index, scripts, values, num_values, tapleaf_script, tapleaf_script_len,
                    key_version, codesep_pos, annex, annex_len, sighash, flags, bytes_out, out_len]
            for i, arg in case:
                args[i] = arg
            ret = wally_tx_get_btc_taproot_signature_hash(*args)
            self.assertEqual(ret, WALLY_EINVAL)


if __name__ == '__main__':
    unittest.main()
