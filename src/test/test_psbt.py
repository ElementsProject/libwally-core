import binascii
import json
import unittest
from util import *

class PSBTTests(unittest.TestCase):

    def test_serialization(self):
        """Testing serialization and deserialization"""
        with open(root_dir + 'src/data/psbt.json', 'r') as f:
            d = json.load(f)
            invalids = d['invalid']
            valids = d['valid']
            creators = d['creator']
            signers = d['signer']
            inval_signers = d['inval_signer']
            combiners = d['combiner']
            finalizers = d['finalizer']
            extractors = d['extractor']

        for invalid in invalids:
            self.assertEqual(WALLY_EINVAL, wally_psbt_from_base64(invalid.encode('utf-8'), pointer(wally_psbt())))

        for valid in valids:
            psbt = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(valid['psbt'].encode('utf-8'), psbt))
            ret, reser = wally_psbt_to_base64(psbt, 0)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(valid['psbt'], reser)
            ret, length = wally_psbt_get_length(psbt, 0)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(length, valid['len'])

        for creator in creators:
            psbt = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 2, 0, psbt))

            tx = pointer(wally_tx())
            self.assertEqual(WALLY_OK, wally_tx_init_alloc(2, 0, 2, 2, tx))
            for txin in creator['inputs']:
                tx_in = pointer(wally_tx_input())
                txid = binascii.unhexlify(txin['txid'])[::-1]
                self.assertEqual(WALLY_OK, wally_tx_input_init_alloc(txid, len(txid), txin['vout'], 0xffffffff, None, 0, None, tx_in))
                self.assertEqual(WALLY_OK, wally_tx_add_input(tx, tx_in))
            for txout in creator['outputs']:
                addr = txout['addr']
                amt = txout['amt']
                spk, spk_len = make_cbuffer('00' * (32 + 2))
                ret, written = wally_addr_segwit_to_bytes(addr.encode('utf-8'), 'bcrt'.encode('utf-8'), 0, spk, spk_len)
                self.assertEqual(WALLY_OK, ret)
                output = pointer(wally_tx_output())
                self.assertEqual(WALLY_OK, wally_tx_output_init_alloc(amt, spk, written, output))
                self.assertEqual(WALLY_OK, wally_tx_add_output(tx, output))

            self.assertEqual(WALLY_OK, wally_psbt_set_global_tx(psbt, tx))
            # wally_psbt_set_global_tx() reserves space for but does not add
            # PSBT input and output values. Set the count here to use the
            # empty reserved ones for this test.
            psbt.contents.num_inputs = psbt.contents.tx.contents.num_inputs
            psbt.contents.num_outputs = psbt.contents.tx.contents.num_outputs
            ret, ser = wally_psbt_to_base64(psbt, 0)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(creator['result'], ser)

        for combiner in combiners:
            psbt = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(combiner['combine'][0].encode('utf-8'), psbt))
            for src_b64 in combiner['combine'][1:]:
                src = pointer(wally_psbt())
                self.assertEqual(WALLY_OK, wally_psbt_from_base64(src_b64.encode('utf-8'), src))
                self.assertEqual(WALLY_OK, wally_psbt_combine(psbt, src))
                self.assertEqual(WALLY_OK, wally_psbt_free(src))
            ret, psbt_b64 = wally_psbt_to_base64(psbt, 0)
            self.assertEqual(combiner['result'], psbt_b64)

        for signer in signers:
            psbt = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(signer['psbt'].encode('utf-8'), psbt))
            for priv in signer['privkeys']:
                buf, buf_len = make_cbuffer('00'*32)
                self.assertEqual(WALLY_OK, wally_wif_to_bytes(priv.encode('utf-8'), 0xEF, 0, buf, buf_len))
                self.assertEqual(WALLY_OK, wally_psbt_sign(psbt, buf, buf_len))

            ret, reser = wally_psbt_to_base64(psbt, 0)
            self.assertEqual(WALLY_OK, ret)
            # Check that we can *demarshal* the signed PSBT (some bugs only appear here)
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(reser, psbt))
            self.assertEqual(signer['result'], reser)

        for inval_signer in inval_signers:
            psbt = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(inval_signer['psbt'].encode('utf-8'), psbt))

            for priv in inval_signer['privkeys']:
                buf, buf_len = make_cbuffer('00'*32)
                self.assertEqual(WALLY_OK, wally_wif_to_bytes(priv.encode('utf-8'), 0xEF, 0, buf, buf_len))
                self.assertEqual(WALLY_EINVAL, wally_psbt_sign(psbt, buf, buf_len))

        for finalizer in finalizers:
            psbt = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(finalizer['finalize'].encode('utf-8'), psbt))
            self.assertEqual(WALLY_OK, wally_psbt_finalize(psbt))
            ret, reser = wally_psbt_to_base64(psbt, 0)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(finalizer['result'], reser)

        for extractor in extractors:
            psbt = pointer(wally_psbt())
            tx = pointer(wally_tx())
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(extractor['extract'].encode('utf-8'), psbt))
            self.assertEqual(WALLY_OK, wally_psbt_extract(psbt, tx))
            ret, reser = wally_tx_to_hex(tx, 1)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(extractor['result'], reser)

if __name__ == '__main__':
    unittest.main()
