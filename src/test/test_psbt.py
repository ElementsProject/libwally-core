import binascii
import base64
import json
import os
import unittest
from util import *

class PSBTTests(unittest.TestCase):

    def test_serialization(self):
        """Testing serialization and deserialization"""
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/psbt.json')) as f:
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
            ret, reser = wally_psbt_to_base64(psbt)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(valid['psbt'], reser)
            ret, length = wally_psbt_get_length(psbt)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(length, valid['len'])

        for creator in creators:
            psbt = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 2, 0, psbt))

            tx = pointer(wally_tx())
            self.assertEqual(WALLY_OK, wally_tx_init_alloc(2, 0, 2, 2, tx))
            for txin in creator['inputs']:
                input = pointer(wally_tx_input())
                txid = binascii.unhexlify(txin['txid'])[::-1]
                self.assertEqual(WALLY_OK, wally_tx_input_init_alloc(txid, len(txid), txin['vout'], 0xffffffff, None, 0, None, input))
                self.assertEqual(WALLY_OK, wally_tx_add_input(tx, input))
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
            ret, ser = wally_psbt_to_base64(psbt)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(creator['result'], ser)

        for combiner in combiners:
            to_combine = []
            for comb in combiner['combine']:
                psbt = pointer(wally_psbt())
                self.assertEqual(WALLY_OK, wally_psbt_from_base64(comb.encode('utf-8'), psbt))
                to_combine.append(psbt.contents)
            combined = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_combine_psbts((wally_psbt * len(to_combine))(*to_combine), len(to_combine), combined))
            ret, comb_ser = wally_psbt_to_base64(combined)
            self.assertEqual(combiner['result'], comb_ser)

        for signer in signers:
            psbt = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(signer['psbt'].encode('utf-8'), psbt))
            for priv in signer['privkeys']:
                buf, buf_len = make_cbuffer('00'*32)
                self.assertEqual(WALLY_OK, wally_wif_to_bytes(priv.encode('utf-8'), 0xEF, 0, buf, buf_len))
                self.assertEqual(WALLY_OK, wally_sign_psbt(psbt, buf, buf_len))

            ret, reser = wally_psbt_to_base64(psbt)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(signer['result'], reser)

        for inval_signer in inval_signers:
            psbt = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(inval_signer['psbt'].encode('utf-8'), psbt))
            for priv in inval_signer['privkeys']:
                buf, buf_len = make_cbuffer('00'*32)
                self.assertEqual(WALLY_OK, wally_wif_to_bytes(priv.encode('utf-8'), 0xEF, 0, buf, buf_len))
                self.assertEqual(WALLY_EINVAL, wally_sign_psbt(psbt, buf, buf_len))

        for finalizer in finalizers:
            psbt = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(finalizer['finalize'].encode('utf-8'), psbt))
            self.assertEqual(WALLY_OK, wally_finalize_psbt(psbt))
            ret, reser = wally_psbt_to_base64(psbt)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(finalizer['result'], reser)

        for extractor in extractors:
            psbt = pointer(wally_psbt())
            tx = pointer(wally_tx())
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(extractor['extract'].encode('utf-8'), psbt))
            self.assertEqual(WALLY_OK, wally_extract_psbt(psbt, tx))
            ret, reser = wally_tx_to_hex(tx, 1)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(extractor['result'], reser)

if __name__ == '__main__':
    unittest.main()
