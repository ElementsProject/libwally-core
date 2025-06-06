import unittest
from util import *
import json

# the private part of our blinding key
UNBLIND_OUR_SK, UNBLIND_OUR_SK_LEN = make_cbuffer('e8ba74f899e6b06da05fb255511c7adcea41f186326ef4fc45290fa8043f7af5')
# the sender's pubkey used to blind the output
UNBLIND_SENDER_PK, UNBLIND_SENDER_PK_LEN = make_cbuffer('0378d8b53305ed6482db0c8f5eb8b0ca3d5c314d7773c584faa8cf587ee8137244')
# amount rangeproof
UNBLIND_RANGEPROOF, UNBLIND_RANGEPROOF_LEN = make_cbuffer('602300000000000000010d28013bd6c293ff8791d172520c5ecdceb4d4c4bbeac9d1f016cd9069624d606d5fe0641e36cce10328f2c9c481a7342c27ef81b0b8533a72b289dfc18942651c4c31b0497bcc21444fbf73214755791c32dba25508f20f33d2a171fb46f360cfc63677df9f696a4566ce9d305ff47d51a73c3e8ee56cd6b6a1b62bf606068da2145a3805de1dfbe8de65b997d261e27f7ce5a4233b410bb2a17fe903a3a6f5a907d0e2cc1b0c16dde9a4ed99c59b2e3f3db331c4d910ffb87fa7696136c1a7562fa32f84ef4b6e7a298053dc84a851798503200a006cbf403a741a13507c9f2c57ae2139b08974777f0245e5cb5c890626c6041d65bd15c0220f20f3823a88364d9f50dddeae1de77f5015c8749622a1e15d242b029a4810374dfb3297ce87f8e16bd84e4147bc03a7279c9a7cfb85669ea51a2f04e1126b150bd995191284d1ffa5fb904501d0076d179cbef13912bdc9ecd3db4c40ec2ecb1b6987d6d526443d02a35c260d721b321535ff4749bba2cb44a928e96af0955d68159ca501758abb3c97e5781e20d2e74bfdb8f1e342fe7023181006ba3ea3624d9ce831f998c2d9953475250726f940e5543204e447c0afc2e00b7ff08564db6e6933b1a82ce30c7bed97f3b58a154a932fb229533317edcc9bb4b338e43b2ac5a5c27380d7523230f7f99729a4000' +
                                 '285b4427c9d79dd6508a81052106107a99b224e2e65fe5b5f94b71323f8cb55f8eda2283e464f35cc00dad0e5d6cfd104eef5c180683eb28040502937d1377d1c07f31d30ba7c3a11a88560078646c0b431fca020dde44b2f6258183aca426f67c3bc235d59a1680d1bc124dac0cbf4a7147d28dc7093e72dcd7259ecc75118d6b6fdcda5c66b761afdc749b8f27bc0d676e719df2850827389809215b96fc19458390892f98cc175e36cab798215f93d473561aaed05536272e97ac25a2e5915b543f058a03c9827d42525ecf6b8bb7f83440a9f2e7f6a672a918e291ec662eb044a76281c35369e1ce1a8fa78751691c3e17e409ea7c4272199aecac2ba51e7493941d5be901ff3daf66714bb066d8c00c25fbef8be50b7edfad99e96a27302f0850db4083a3c2bd7ffa367b3cb36ae3d64ed138a6b9b9da26e4b0d2beb9e6570beca85bdb5fe562122baa2791e34d0f102d15d3dfa293232fd0656012977f71c4e9f7f7579bf1d00cc414dc263a3189d9f508a8b16019f575150a632610a3dc1b50ec880cc8453a55af786ed86c0163501f0709a79565d273851a86ae49273adad202cc0f782f67953da4c442faefd903edbb30efe9489ace0802dd8063fdac5d9a9c9885536f8bfb86de8d65296cab722958366ae74c0e38e0b197eba10a930335d2f0945841cb66eea0958fc1eef40eeff' +
                                 '80b6f87f3e46c3990b2ad27b3c7c89ac99f66e84458fc07ff09ed5ee96753b2fcbad4da7d0718fdc455c0fe9ebc614f072fb1da072564ba881044496f8757099663f36a269da6778a3d03904d0fa7619192cf28639cd359e1a7fd5a9a8e207d505c0764602a824d1b1540f17ab75d81e7435501018193fc6cbbee3921c8806b4f81246367fe523d9e32f8e5be8da29041940db0bcf0b2ae604ec665fea1e10b861e2c078aa09dcebb6cc283ab171598a799787a622fc5ea7ed63b558d020ee8c853f5ba888fd35bc851c1a2873531be58f82ef9d443edb5358698f0e6c4a7b133a22e1dbb4a8bd07bca9d08e0735b702acc9d3dfec7708002892676f738197ebf6790e9531727d98bd199883affc879c3579c05400a4db2e214f824e3ae37cdbc825ef2ec58bd861226bdf9be4bd81a1858d63050f58796d739d901ac4a8c0a29fe90db30ad58d075c5944e88ff2d46edac7e678faf889b4b681c6bf0890708f5e60ca80e5195b94cdae5bc3c89963f7634398d595219a6bfa1f512387b2006e85fdade17adce51d42061107b74a69a8961be3c3de86bd6caa77bb88a1f29b572c1c05b423bdde397cf238746b63f12b7a867baba644c3718acfc963ea2b9c0c96c493ed2fc1e2103c57fdb60dba24f94df7d008f96aaa6bd9f598eaab71c8d597224dd6259ce24b531def3b0c964c9a29f1833' +
                                 '11f5e30b76f667bba242ae11ab40f2e325a63cfcd4fe90f495d9533ef5307938ce2800fe9dfd6ce27590abf0c7e37639befb5751a950552cf19dc968c24dc727ca16cdaabf73ab7fcb14f5d5bd0a8735dd2b6957cd21b3a22c24641d215f5b60e79a5adc1aa06697a1adbc4d375798b586bf954af251c0f3aed359371fc7699a02824801edff2fe5fa63d7d94bae1b8ab02f49917ffadebb6fc8064484178313ce34d0a59ea07026ca5abcf6424e181954383ea820e77f01dc1807aebfde103aab79d49de697b640a2a41dcb3a69f340eb7f98b543694abfc93d35b4153d779811a313b335dac71b3512c4414082b15626a37f0fb82efd62cd23692e88d75501f1ab68a712bae7061a201e6b0caac0de300ea93ff6d52161ea13724d946ae0d3fc0aae0d1987d03a549ea481007546d5c3b89245d8eea2d8fce5b5ac8bde15b327fbc62bef5cd20b09bc5c6de1316a99a9d55c3f462dbe21860f43bca336f7e03c7e1a39af397ebd83571e2a0003be52b7d88404f1e1300dcd8fdd20e740ea0e5b58613dd0b19e219c05ff7d31c3f0c86a1f83b02c2d5e382e27d476f44b484e0dd9e82dfc1567e44e045482938100354722e57a36769d8b91b1d4064cb08c233519d636adf31fa49c75b067437b0ac52152079575b3d2b672433a1b865b5e8d82ad18980adad6cd26224859082e487e0573a8e' +
                                 '24cb9f3e08dd02da28d70f6dd8cb1a029c175776d0db4f40102812fe9d1a32778317b61f27a96a6689ad1787a8b7a3672f9568a3b9f456039243202a1ef55f3a5c64dae11d58dbf931eceab8a21de2e7aaef7f47938d34240999ac3f66fcae1afbbdccffb56e4fbea05b14a6f64da770b3ff95471ce73d26f96b1549a9641d085af574fd9a2dc037382417dbd15c3b4c5c67c91b73fda65be7828e1045b1631a330882180068ad9fced2c8cb154281e584f63966c7ac5127397a10e4de98c6daec5676689db46c2950ebb84fc84d42a30c603df31f7bd1f44f6354217845b25219bf3a4e01674a7404add024bb2d5184582d8ea0a1005aa8e3abd24b0e4069de87c1ccb1654613a4e734eea3b6045025e5902c3e74796ba0911e40c4d814076422ffdb2eb9faf5079638a59d188304ffdd8b1635b585c881c37434e256c6df5193c3720c7973b14541ae7681214bd9387bbcdea3ecafd1103050371224ba5b9992058e7114502886b3dddd2901612a699713f2e0b659c1ffbe04b29971dd277971848c769dfaaa3b96a93b47e7f46e002c3f0ffa3937c36bb4bd034a5dd252ad9d39c70e9862390f5eb2d8aba7a15d6b77b5b027531af282e2cccac117548a8b5ca415595d2e8a2ae400366cfa5400c5bf51a729fd22ed50752b2b03d959bc3f0bef52c17e61ae16536d1d019454d9f6b9a38ff' +
                                 'bc70706ab7fe4908c0bea9427547c8c9d9c4fdb4f25f1f26ea7f0a4a2a487c7639138de55bb2bc6e7d47a0241fbf347dd714767198fe85a0d294b938699f139e6a6f66e6916b566584811115591fa1f5e8561369b07c9155d28619df2537e651fcb4667f07ea5fd884779c7bb81af74b0987125aa915644a17b852b465661d0fcdb108ca76b51350635660f61e3b46df74b6b9877dbfab79fda8191e12a0f51fca7081cc5b91c576a99cba868c034ea04e0b4c2ccabada556187970fe0100f647301958c9771517a558ad6183a3f912b94030561948de2d2c44a3117e489de7b0568eee8bc15820a734a3b745eff696732fb660958b7f15b4298ed683b99dadcf4fbc002ead43fb792922c6a1ad69aa626fc4893daaa3c2ad0f90784f5872a115222472c6b2d1308f0b88486701566c86ee2ad03b3ce06206bfc6b205084469a84dfa7a7861889a5d5990a5f7a5177497e11f95c8af5fd192349b02b66af842f2eb6964b7ce201ecce6e3373e320e316a2844bcf121d409a4f8e3f7e73b02f93ff3601f7c1957aa8c3a34b7')
# scriptPubKey of the output
UNBLIND_SCRIPT, UNBLIND_SCRIPT_LEN = make_cbuffer('76a9145976d83033bde4f12713ae3706b25e92fb608b9188ac')
# asset commitment
UNBLIND_ASSET_COMMITMENT, UNBLIND_ASSET_COMMITMENT_LEN = make_cbuffer('0b9d043d60286407330e12001e539559f6227c9999abf251b7497bba53ac20cd70')
# value commitment
UNBLIND_VALUE_COMMITMENT, UNBLIND_VALUE_COMMITMENT_LEN = make_cbuffer('09b67565b370abf41d81fe0ed6378e7228e9ae01d1b72b69582f83db1fca522148')

UNBLINDED_ASSET, UNBLINDED_ASSET_LEN = make_cbuffer('25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a')
UNBLINDED_ABF, UNBLINDED_ABF_LEN = make_cbuffer('3f2f58e80fbe77e8aad8268f1baebc3548c777ba8271f99ce73210ad993d907d')
UNBLINDED_VBF, UNBLINDED_VBF_LEN = make_cbuffer('51f109e34d0282b6efac36d118131060f7f79b867b67a95bebd087eda2ccd796')

# TODO: expand these tests a little bit...
class ElementsTests(unittest.TestCase):

    def test_asset_unblind(self):
        if not wally_is_elements_build()[1]:
            self.skipTest('Elements support not enabled')

        asset_out, _ = make_cbuffer('00' * 32)
        abf_out, _ = make_cbuffer('00' * 32)
        vbf_out, _ = make_cbuffer('00' * 32)

        args = (
            UNBLIND_SENDER_PK, UNBLIND_SENDER_PK_LEN,
            UNBLIND_OUR_SK, UNBLIND_OUR_SK_LEN,
            UNBLIND_RANGEPROOF, UNBLIND_RANGEPROOF_LEN,
            UNBLIND_VALUE_COMMITMENT, UNBLIND_VALUE_COMMITMENT_LEN,
            UNBLIND_SCRIPT, UNBLIND_SCRIPT_LEN,
            UNBLIND_ASSET_COMMITMENT, UNBLIND_ASSET_COMMITMENT_LEN,
            asset_out, 32,
            abf_out, 32,
            vbf_out, 32
        )
        ret, value_out = wally_asset_unblind(*args)
        self.assertEqual((ret, value_out, asset_out, abf_out, vbf_out),
                         (WALLY_OK, 80000000, UNBLINDED_ASSET, UNBLINDED_ABF, UNBLINDED_VBF))

    def test_asset_unblind_with_nonce(self):
        if not wally_is_elements_build()[1]:
            self.skipTest('Elements support not enabled')

        out_nonce_hash, _ = make_cbuffer('00'*32)
        ret = wally_ecdh_nonce_hash(UNBLIND_SENDER_PK, UNBLIND_SENDER_PK_LEN,
                                    UNBLIND_OUR_SK, UNBLIND_OUR_SK_LEN,
                                    out_nonce_hash, len(out_nonce_hash))
        self.assertEqual(ret, WALLY_OK)

        out_nonce, _ = make_cbuffer('00'*32)
        ret = wally_ecdh(UNBLIND_SENDER_PK, UNBLIND_SENDER_PK_LEN,
                         UNBLIND_OUR_SK, UNBLIND_OUR_SK_LEN,
                         out_nonce, len(out_nonce))
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(wally_sha256(out_nonce, 32, out_nonce, 32), WALLY_OK)
        # ecdh_nonce_hash helper and manual hashing of the nonce must match
        self.assertEqual(out_nonce, out_nonce_hash)

        asset_out, _ = make_cbuffer('00' * 32)
        abf_out, _ = make_cbuffer('00' * 32)
        vbf_out, _ = make_cbuffer('00' * 32)

        args = (
            out_nonce, len(out_nonce),
            UNBLIND_RANGEPROOF, UNBLIND_RANGEPROOF_LEN,
            UNBLIND_VALUE_COMMITMENT, UNBLIND_VALUE_COMMITMENT_LEN,
            UNBLIND_SCRIPT, UNBLIND_SCRIPT_LEN,
            UNBLIND_ASSET_COMMITMENT, UNBLIND_ASSET_COMMITMENT_LEN,
            asset_out, 32,
            abf_out, 32,
            vbf_out, 32
        )
        ret, value_out = wally_asset_unblind_with_nonce(*args)
        self.assertEqual((ret, value_out, asset_out, abf_out, vbf_out),
                         (WALLY_OK, 80000000, UNBLINDED_ASSET, UNBLINDED_ABF, UNBLINDED_VBF))

    def test_asset_generator_from_bytes(self):
        if not wally_is_elements_build()[1]:
            self.skipTest('Elements support not enabled')

        generator, generator_len = make_cbuffer('00' * 33)

        # Blind the unblinded asset with its blinding factor
        ret = wally_asset_generator_from_bytes(UNBLINDED_ASSET, UNBLINDED_ASSET_LEN,
                                               UNBLINDED_ABF, UNBLINDED_ABF_LEN,
                                               generator, generator_len)
        self.assertEqual((ret, generator), (WALLY_OK, UNBLIND_ASSET_COMMITMENT))

        # Parse the blinded commitment directly as a generator
        ret = wally_asset_generator_from_bytes(UNBLIND_ASSET_COMMITMENT, UNBLIND_ASSET_COMMITMENT_LEN,
                                               None, 0,
                                               generator, generator_len)
        self.assertEqual((ret, generator), (WALLY_OK, UNBLIND_ASSET_COMMITMENT))

        # Create an unblinded generator from the asset
        expected, expected_len = make_cbuffer('0a73d9600e05986acd3c0c6521e72a198b0155e8a79d335035ff0432f26163f17e')
        ret = wally_asset_generator_from_bytes(UNBLINDED_ASSET, UNBLINDED_ASSET_LEN,
                                               None, 0,
                                               generator, generator_len)
        self.assertEqual((ret, generator), (WALLY_OK, expected))

        # Create an unblinded generator from an explicit asset commitment
        tag, tag_len = make_cbuffer(h(bytearray([0x1]) + UNBLINDED_ASSET))
        ret = wally_asset_generator_from_bytes(tag, tag_len,
                                               None, 0,
                                               generator, generator_len)
        self.assertEqual((ret, generator), (WALLY_OK, expected))

    def test_blinding(self):
        if not wally_is_elements_build()[1]:
            self.skipTest('Elements support not enabled')

        value = 80000000

        # asset_value_commitment
        value_commitment, value_commitment_len = make_cbuffer('00' * 33)
        ret = wally_asset_value_commitment(value, UNBLINDED_VBF, len(UNBLINDED_VBF),
                                           UNBLIND_ASSET_COMMITMENT, UNBLIND_ASSET_COMMITMENT_LEN,
                                           value_commitment, value_commitment_len)
        self.assertEqual((ret, value_commitment), (WALLY_OK, UNBLIND_VALUE_COMMITMENT))

        # asset_rangeproof
        rangeproof, rangeproof_len = make_cbuffer('00' * 5134)
        ret, written = wally_asset_rangeproof(value, UNBLIND_SENDER_PK, UNBLIND_SENDER_PK_LEN,
                                              UNBLIND_OUR_SK, UNBLIND_OUR_SK_LEN,
                                              UNBLINDED_ASSET, UNBLINDED_ASSET_LEN,
                                              UNBLINDED_ABF, UNBLINDED_ABF_LEN,
                                              UNBLINDED_VBF, UNBLINDED_VBF_LEN,
                                              UNBLIND_VALUE_COMMITMENT, UNBLIND_VALUE_COMMITMENT_LEN,
                                              None, 0,
                                              UNBLIND_ASSET_COMMITMENT, UNBLIND_ASSET_COMMITMENT_LEN,
                                              1, 0, 52, rangeproof, rangeproof_len)
        self.assertEqual(ret, WALLY_OK)
        rangeproof_len = written

        # explicit_rangeproof
        explicit_proof, explicit_proof_len = make_cbuffer('00' * 73)
        nonce, nonce_len = make_cbuffer('44' * 32) # Random, in normal usage

        ret, written = wally_explicit_rangeproof(value, nonce, nonce_len,
                                                 UNBLINDED_VBF, len(UNBLINDED_VBF),
                                                 UNBLIND_VALUE_COMMITMENT, len(UNBLIND_VALUE_COMMITMENT),
                                                 UNBLIND_ASSET_COMMITMENT, UNBLIND_ASSET_COMMITMENT_LEN,
                                                 explicit_proof, explicit_proof_len)
        self.assertEqual((ret, written), (WALLY_OK, 73))

        # explicit_rangeproof_verify
        for v, expected in [
            (value + 1, WALLY_EINVAL),
            (value,     WALLY_OK),
            (value - 1, WALLY_EINVAL)]:
            ret = wally_explicit_rangeproof_verify(explicit_proof, explicit_proof_len, v,
                                                   UNBLIND_VALUE_COMMITMENT, len(UNBLIND_VALUE_COMMITMENT),
                                                   UNBLIND_ASSET_COMMITMENT, UNBLIND_ASSET_COMMITMENT_LEN)
            self.assertEqual(ret, expected)

        # asset_surjectionproof_size
        ret, expected_proof_len = wally_asset_surjectionproof_size(1)
        self.assertEqual((ret, expected_proof_len), (WALLY_OK, 67))

        # asset_surjectionproof
        output_abf, output_abf_len = make_cbuffer('91' * 32)
        output_generator, output_generator_len = make_cbuffer('00' * 33)
        ret = wally_asset_generator_from_bytes(UNBLINDED_ASSET, UNBLINDED_ASSET_LEN,
                                               output_abf, output_abf_len,
                                               output_generator, output_generator_len)
        self.assertEqual(ret, WALLY_OK)

        entropy, entropy_len = make_cbuffer('34' * 32)
        surjectionproof, surjectionproof_len = make_cbuffer('00' * expected_proof_len)
        args = [ UNBLINDED_ASSET, UNBLINDED_ASSET_LEN,
                 output_abf, output_abf_len,
                 output_generator, output_generator_len,
                 entropy, entropy_len,
                 UNBLINDED_ASSET, UNBLINDED_ASSET_LEN,
                 UNBLINDED_ABF, UNBLINDED_ABF_LEN,
                 UNBLIND_ASSET_COMMITMENT, UNBLIND_ASSET_COMMITMENT_LEN ]
        ret, proof_len = wally_asset_surjectionproof_len(*args)
        self.assertEqual((ret, proof_len), (WALLY_OK, expected_proof_len))
        ret, written = wally_asset_surjectionproof(*args + [surjectionproof, surjectionproof_len])
        self.assertEqual((ret, written), (WALLY_OK, expected_proof_len))

        # explicit_surjectionproof
        ASSET_EXPLICIT_SURJECTIONPROOF_LEN = 67
        explicit_sjproof, explicit_sjproof_len = make_cbuffer('00' * ASSET_EXPLICIT_SURJECTIONPROOF_LEN)
        ret = wally_explicit_surjectionproof(UNBLINDED_ASSET, UNBLINDED_ASSET_LEN,
                                             output_abf, output_abf_len,
                                             output_generator, output_generator_len,
                                             explicit_sjproof, explicit_sjproof_len)
        self.assertEqual(ret, WALLY_OK)

        # explicit_surjectionproof_verify
        for good, expected in [(True, WALLY_OK), (False, WALLY_ERROR)]:
            asset = UNBLINDED_ASSET if good else UNBLINDED_ABF # Use abf as an example of bad asset
            ret = wally_explicit_surjectionproof_verify(explicit_sjproof, explicit_sjproof_len,
                                                        asset, UNBLINDED_ASSET_LEN,
                                                        output_generator, output_generator_len)
            self.assertEqual(ret, expected)

        # wally_asset_scalar_offset
        SCALAR_OFFSET_LEN = 32
        offset, offset_len = make_cbuffer('00' * SCALAR_OFFSET_LEN)
        ret = wally_asset_scalar_offset(value, UNBLINDED_ABF, UNBLINDED_ABF_LEN,
                                        UNBLINDED_VBF, UNBLINDED_VBF_LEN, offset, offset_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(h(offset),
                         utf8('4e5f3ca8aa2048eeacc8c300e3d63ca92048f407264352bee2fb15bd44349c45'))
        self.assertEqual(wally_ec_scalar_verify(offset, offset_len), WALLY_OK)

    def test_deterministic_blinding_factors(self):
        if not wally_is_elements_build()[1]:
            self.skipTest('Elements support not enabled')

        # Test vector from:
        # https://github.com/Blockstream/Jade/blob/master/test_data/liquid_txn_ledger_compare.json
        with open(root_dir + 'src/data/liquid_txn_ledger_compare.json', 'r') as f:
            JSON = json.load(f)
        master_key_hex = 'afacc503637e85da661ca1706c4ea147f1407868c48d8f92dd339ac272293cdc'
        master_key, master_key_len = make_cbuffer(master_key_hex)
        tx = pointer(wally_tx())
        tx_flags = 0x3 # WALLY_TX_FLAG_USE_WITNESS | WALLY_TX_FLAG_USE_ELEMENTS
        tx_hex = JSON['input']['txn']
        tx_hash_prevout = utf8('7e78263a58236ffd160ee5a2c58c18b71637974aa95e1c72070b08208012144f')
        self.assertEqual(WALLY_OK, wally_tx_from_hex(tx_hex, tx_flags, tx))
        # hashPrevouts
        hp, hp_len = make_cbuffer('00'*32)
        ret = wally_tx_get_hash_prevouts(tx, 0, 0xffffffff, hp, hp_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(h(hp[:hp_len]), tx_hash_prevout)
        # ABF/VBF. Note we don't expect the last VBF to match
        out, out_len = make_cbuffer('00'*64)
        commitments = JSON['input']['trusted_commitments'][:-1] # Skip Fee output
        for n, output in enumerate(commitments):
            abf, vbf = [output[k] for k in ('abf', 'vbf')]
            for fn, o_len, expected in [
                (wally_asset_blinding_key_to_abf_vbf, 64, abf + vbf),
                (wally_asset_blinding_key_to_abf,     32, abf),
                (wally_asset_blinding_key_to_vbf,     32, vbf)]:
                ret = fn(master_key, master_key_len, hp, hp_len, n, out, o_len)
                self.assertEqual(ret, WALLY_OK)
                if n == len(commitments) - 1:
                    if fn in [wally_asset_blinding_key_to_abf_vbf, wally_asset_blinding_key_to_vbf]:
                        continue # Skip final VBF
                self.assertEqual(h(out[:o_len]), utf8(expected))

    def test_elip150_blinding_keys(self):
        if not wally_is_elements_build()[1]:
            self.skipTest('Elements support not enabled')

        # Ensure tweaking private and public keys results in the same key
        priv_key, priv_key_len = make_cbuffer('66'*32)
        pub_key, pub_key_len = make_cbuffer('00'*33)
        ret = wally_ec_public_key_from_private_key(priv_key, priv_key_len,
                                                   pub_key, pub_key_len)
        self.assertEqual(WALLY_OK, ret)
        script, script_len = make_cbuffer('11'*40)
        out_priv, out_priv_len = make_cbuffer('00'*32)
        out_pub, out_pub_len = make_cbuffer('00'*33)
        ret = wally_elip150_private_key_to_ec_private_key(priv_key, priv_key_len,
                                                          script, script_len,
                                                          out_priv, out_priv_len)
        self.assertEqual(WALLY_OK, ret)
        ret = wally_ec_public_key_from_private_key(out_priv, out_priv_len,
                                                   out_pub, out_pub_len)
        self.assertEqual(WALLY_OK, ret)
        expected_pubkey = h(out_pub)

        ret = wally_elip150_private_key_to_ec_public_key(priv_key, priv_key_len,
                                                         script, script_len,
                                                         out_pub, out_pub_len)
        self.assertEqual(WALLY_OK, ret)
        self.assertEqual(expected_pubkey, h(out_pub))

        ret = wally_elip150_public_key_to_ec_public_key(pub_key, pub_key_len,
                                                        script, script_len,
                                                        out_pub, out_pub_len)
        self.assertEqual(WALLY_OK, ret)
        self.assertEqual(expected_pubkey, h(out_pub))


    def test_elements_tx_weights(self):
        if not wally_is_elements_build()[1]:
            self.skipTest('Elements support not enabled')

        # Test the elements weight discount
        with open(root_dir + 'src/data/elip200_vectors.json', 'r') as f:
            JSON = json.load(f)
        for case in JSON['cases']:
            tx = pointer(wally_tx())
            tx_flags = 0x3 # WALLY_TX_FLAG_USE_WITNESS | WALLY_TX_FLAG_USE_ELEMENTS
            self.assertEqual(WALLY_OK, wally_tx_from_hex(case['tx'], tx_flags, tx))
            self.assertEqual((WALLY_OK, case['weight']), wally_tx_get_weight(tx))
            discount = case['weight'] - case['discount_weight']
            self.assertEqual((WALLY_OK, discount), wally_tx_get_elements_weight_discount(tx, 0))


if __name__ == '__main__':
    unittest.main()
