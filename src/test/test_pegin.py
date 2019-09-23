import unittest
from util import *


SCRIPT_HASH160 = 0x1
SCRIPT_SHA256 = 0x2
FLAG_CHECKSUM = 0x1


class PeginTests(unittest.TestCase):


    def get_pegin_address(self):
        """ uses same strategy as elementsd 0.18 to generate the mainchain address and claim script """

        pk, pk_len = make_cbuffer('02dc07c7235ad59ebb556643911f08cc143eb2ee061d41b7f105a2167dd3137ea4')

        claim_script, claim_script_len = make_cbuffer('00'*22)
        self.assertEqual(wally_witness_program_from_bytes(pk, pk_len, SCRIPT_HASH160, claim_script, claim_script_len)[0], WALLY_OK)

        # federation script for regtest
        federation_script, federation_script_len = make_cbuffer('51')
        contract_script, contract_script_len = make_cbuffer('00'*federation_script_len)
        self.assertEqual(wally_elements_pegin_contract_script_from_bytes(federation_script, federation_script_len,
                                                                         claim_script, claim_script_len,
                                                                         0, contract_script, contract_script_len)[0], WALLY_OK)
        mainchain_script, mainchain_script_len = make_cbuffer('00'*34)
        self.assertEqual(wally_witness_program_from_bytes(contract_script, contract_script_len, SCRIPT_SHA256, mainchain_script, mainchain_script_len)[0], WALLY_OK)

        script, script_len = make_cbuffer('00'*20)
        self.assertEqual(wally_hash160(mainchain_script, mainchain_script_len, script, script_len), WALLY_OK)

        ret, mainchain_address = wally_base58_from_bytes(chr(196)+script, script_len+1, FLAG_CHECKSUM)
        self.assertEqual(ret, WALLY_OK)

        return mainchain_address, claim_script


    def test_pegin_tx(self):
        # pegin tx from createrawpegin
        pegin_tx = '0200000001018c78b1b1e379bb79cff9c96ef92742ceb7cfe3c144cd7b4a2c472234758b94340000004000ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5d386001600149ce668ef355bb7bbb4dc532d6253b1dc620c864d0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000000d7a000000000000000000060800e1f505000000002025b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f16001447dc2241f735ba3e39cbbc30883bc79fbe79b9308a020000000194e7d81a9ac87b725ec10e6c59918c52d39f61e4fa2fa08c7fa2d078b38c468500000000171600146b84062093cd6d4f7aef0f7315201f8b00d975aefeffffff0200e1f5050000000017a91472c44f957fc011d97e3406667dca5b1c930c402687188542060100000017a9145db12bf4a1fbce5b1bb232277d221abe271db81f873b00000097000000207c390a46698af24ef305b49f33ccba92e8b800677baf2a64d9ca059302f657101c69b46c7b062fbef3bfdd959518aae4875bf4bd88e97380020fea9d8535388bf2d38b5dffff7f2000000000020000000266bc307341d2cfa75b79b17a74ae1e3e00b5746e8d04bd311ecbe11bf1b739bb8c78b1b1e379bb79cff9c96ef92742ceb7cfe3c144cd7b4a2c472234758b9434010500000000'

        # pegin tx from claimpegin (signed)
        pegin_tx_signed = '0200000001018c78b1b1e379bb79cff9c96ef92742ceb7cfe3c144cd7b4a2c472234758b94340000004000ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5d386001600149ce668ef355bb7bbb4dc532d6253b1dc620c864d0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000000d7a00000000000000000247304402207ee3f5a6bf00f0662098c1d6d812cba4b16229ae7a87a081b08eea1368dcdc0c0220481facf46396c9ee079fa09d0cbeda5255f44386a945ac6112eb25e598fdebe0012102dc07c7235ad59ebb556643911f08cc143eb2ee061d41b7f105a2167dd3137ea4060800e1f505000000002025b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f16001447dc2241f735ba3e39cbbc30883bc79fbe79b9308a020000000194e7d81a9ac87b725ec10e6c59918c52d39f61e4fa2fa08c7fa2d078b38c468500000000171600146b84062093cd6d4f7aef0f7315201f8b00d975aefeffffff0200e1f5050000000017a91472c44f957fc011d97e3406667dca5b1c930c402687188542060100000017a9145db12bf4a1fbce5b1bb232277d221abe271db81f873b00000097000000207c390a46698af24ef305b49f33ccba92e8b800677baf2a64d9ca059302f657101c69b46c7b062fbef3bfdd959518aae4875bf4bd88e97380020fea9d8535388bf2d38b5dffff7f2000000000020000000266bc307341d2cfa75b79b17a74ae1e3e00b5746e8d04bd311ecbe11bf1b739bb8c78b1b1e379bb79cff9c96ef92742ceb7cfe3c144cd7b4a2c472234758b9434010500000000'

        # proof from the btc transaction spending to mainchain address (TODO: generate these in wally)
        tx_out_proof, tx_out_proof_len = make_cbuffer('000000207c390a46698af24ef305b49f33ccba92e8b800677baf2a64d9ca059302f657101c69b46c7b062fbef3bfdd959518aae4875bf4bd88e97380020fea9d8535388bf2d38b5dffff7f2000000000020000000266bc307341d2cfa75b79b17a74ae1e3e00b5746e8d04bd311ecbe11bf1b739bb8c78b1b1e379bb79cff9c96ef92742ceb7cfe3c144cd7b4a2c472234758b94340105')

        # static data from the chain
        genesis_block_hash, genesis_block_hash_len = make_cbuffer('0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206')
        asset, asset_len =  make_cbuffer('5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225')

        mainchain_address, claim_script = self.get_pegin_address()

        value, value_len = make_cbuffer('00'*9)
        self.assertEqual(wally_tx_confidential_value_from_satoshi(10**8, value, value_len), WALLY_OK)

        # the BTC transaction spending to mainchain address
        btc_tx_hex = '0200000000010194e7d81a9ac87b725ec10e6c59918c52d39f61e4fa2fa08c7fa2d078b38c468500000000171600146b84062093cd6d4f7aef0f7315201f8b00d975aefeffffff0200e1f5050000000017a91472c44f957fc011d97e3406667dca5b1c930c402687188542060100000017a9145db12bf4a1fbce5b1bb232277d221abe271db81f870247304402204bcb580487d99b21408bee85ff18ef27e7c0b9286209c79e6f8334acb37ae76c0220134d48882744c57d30a199613f238b27045623322daad58466374f9990732d450121037f2cefc51b3c2e10120978a68e389464abb67016b39f5cb3811b7ae552fd93883b000000'
        tx_p = pointer(wally_tx())
        self.assertEqual(wally_tx_from_hex(btc_tx_hex, 0, tx_p), WALLY_OK)

        # strip the witness data from the BTC transaction
        ret, length = wally_tx_get_length(tx_p[0], 0)
        self.assertEqual(ret, WALLY_OK)
        tx_btc_no_witness, tx_btc_no_witness_len = make_cbuffer('00'*length)
        self.assertEqual((WALLY_OK, length), wally_tx_to_bytes(tx_p[0], 0, tx_btc_no_witness, tx_btc_no_witness_len))

        # create the pegin witness stack
        pegin_witness_p = pointer(wally_tx_witness_stack())
        self.assertEqual(wally_tx_witness_stack_init_alloc(5, pegin_witness_p), WALLY_OK)
        for witness, witness_len in ((value[1:][::-1], value_len-1),
                                     (asset[::-1], asset_len),
                                     (genesis_block_hash[::-1], genesis_block_hash_len),
                                     (claim_script, len(claim_script)),
                                     (tx_btc_no_witness, tx_btc_no_witness_len),
                                     (tx_out_proof, tx_out_proof_len)):
            self.assertEqual(wally_tx_witness_stack_add(pegin_witness_p[0], witness, witness_len), WALLY_OK)

        tx = wally_tx(2)

        # the BTC transaction id
        txhash, txhash_len = make_cbuffer('34948b753422472c4a7bcd44c1e3cfb7ce4227f96ec9f9cf79bb79e3b1b1788c')
        self.assertEqual(wally_tx_add_elements_raw_input(tx, txhash[::-1], txhash_len,
                                                         0 | 1 << 30, 0xffffffff, None, 0, wally_tx_witness_stack(),
                                                         None, 0, None, 0, None, 0, None, 0, None, 0, None, 0, pegin_witness_p[0], 0), WALLY_OK)

        unconfidential_satoshi, unconfidential_satoshi_len = make_cbuffer('00'*9)
        self.assertEqual(wally_tx_confidential_value_from_satoshi(99996550, unconfidential_satoshi, unconfidential_satoshi_len), WALLY_OK)

        # witness_v0_keyhash as usually done by elementsd
        script, script_len = make_cbuffer('00149ce668ef355bb7bbb4dc532d6253b1dc620c864d')

        self.assertEqual(wally_tx_add_elements_raw_output(tx, script, script_len, chr(0x1)+asset[::-1], asset_len+1,
                                                          unconfidential_satoshi, unconfidential_satoshi_len, None, 0, None, 0, None, 0, 0), WALLY_OK)

        self.assertEqual(wally_tx_confidential_value_from_satoshi(3450, unconfidential_satoshi, unconfidential_satoshi_len), WALLY_OK)
        self.assertEqual(wally_tx_add_elements_raw_output(tx, None, 0, chr(0x1)+asset[::-1], asset_len+1,
                                                          unconfidential_satoshi, unconfidential_satoshi_len, None, 0, None, 0, None, 0, 0), WALLY_OK)

        # signing key
        priv_key, priv_key_len = make_cbuffer('5fa063a03c1e236fa03fa33f099fc3412535891b853ed04c196c0ac9abaa64aa')

        pub_key, pub_key_len = make_cbuffer('00'*33)
        self.assertEqual(wally_ec_public_key_from_private_key(priv_key, priv_key_len, pub_key, pub_key_len), WALLY_OK)

        # uses claim script from getpeginaddress
        redeem_script, redeem_script_len = make_cbuffer('00'*25)
        self.assertEqual(wally_scriptpubkey_p2pkh_from_bytes(claim_script[2:], len(claim_script)-2, 0, redeem_script, redeem_script_len)[0], WALLY_OK)

        # sign transaction
        unconfidential_satoshi, unconfidential_satoshi_len = make_cbuffer('00'*9)
        self.assertEqual(wally_tx_confidential_value_from_satoshi(10**8, unconfidential_satoshi, unconfidential_satoshi_len), WALLY_OK)
        signature_hash, signature_hash_len = make_cbuffer('00'*32)
        self.assertEqual(wally_tx_get_elements_signature_hash(tx, 0, redeem_script, redeem_script_len,
                                                              unconfidential_satoshi, unconfidential_satoshi_len, 1, 1, signature_hash, signature_hash_len), WALLY_OK)


        sig, sig_len = make_cbuffer('00'*64)
        self.assertEqual(wally_ec_sig_from_bytes(priv_key, priv_key_len, signature_hash, signature_hash_len, 1 | 4, sig, sig_len), WALLY_OK)

        der, der_len = make_cbuffer('00'*72)
        ret, der_len = wally_ec_sig_to_der(sig, sig_len, der, der_len)
        self.assertEqual(ret, WALLY_OK)
        der = der[:der_len] + chr(0x1)
        der_len += 1

        # check transaction matches the createrawpegin generated one
        ret, tx_hex = wally_tx_to_hex(tx, 1)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(tx_hex, pegin_tx)

        # create input witness
        input_witness_p = pointer(wally_tx_witness_stack())
        self.assertEqual(wally_tx_witness_stack_init_alloc(2, input_witness_p), WALLY_OK)
        self.assertEqual(wally_tx_witness_stack_add(input_witness_p[0], der, der_len), WALLY_OK)
        self.assertEqual(wally_tx_witness_stack_add(input_witness_p[0], pub_key, pub_key_len), WALLY_OK)

        self.assertEqual(wally_tx_set_input_witness(tx, 0, input_witness_p[0]), WALLY_OK)

        # check transaction matches the claimpegin generated one
        ret, tx_hex = wally_tx_to_hex(tx, 1)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(tx_hex, pegin_tx_signed)


    def test_contract_script(self):
        expected, expected_len = make_cbuffer('745c87635b2102fead757b12cd8b6503e573482adb0e49cc30222266c361b12e9957e66d7f4afd2102e0c7622b8b17023dc1ed704a0d563e3502eba25c43d66528089a19e0484eb4b1210225bf3e0732cb8c5906fcaac0fc524801c7252a65e21cf430812e4d22b2a46a4e2102fa695d61cdaf931ba743982a495e6f817329024f6ba2539a69b97743b24160ef210260011f030acd4a67f9996479a4982b119e05d049e66d295b0a122cd07c54d9a121030d3e5e6dd06477bb583e75acec88064a3a640d375529638bad8450fb6b23cd0b2102ae90d6157e88a1f7809894e4b9df5feafe84429ddae3fdc3ee98926c1c011f1d2103a952059c9a64cc222bd7c585ab911baedf180f11a47b1fdf520907d8d06c800221026eb5edb29a418faa29f04a50b0235a68fc203b6293535836e19742fd684bf81921034eeca9726f274403e848a644be1fa723fe60747df620bb66c8bb9d516285dd272103d136384a759663e3e4dccb246105278ede9cd8fe19a4f0fc72354d4ba3a5c9bb21028364739ebfbde304781f406a5fe4969faebcb22ccb0bfd68bb0e8a6b96b1612a21039d7c466c2d13fdfafb6a1ad66e25b086bf917cf7d7aab0b17c5e35d1f43382ed210313a87fd6b4f9da2a8f14c4309ce4403fbf948013e0b5ce851ad410c9ffb2817d2102b9acbd3d2300c8e6dffbb325be9e750263bcaa874a79f409a4c9c082afa522b85f6702c00fb275522103cd84a7f1df9b8173b9cb36bbdfc33029e3d36c1e20772149b9735674548e983521029ea41e4e831a30c76ec76eab529f126f8ed5dc0aef6e0eacb4c423191acec58a2102a09eac35c1e879d60d83b7e684c3d13552287aa82253c61cb7df38ceb8694b935368ae')
        federation_script, federation_script_len = make_cbuffer('745c87635b21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b678172612102675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af992102896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d4821029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c2102a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc40102102f8a00b269f8c5e59c67d36db3cdc11b11b21f64b4bffb2815e9100d9aa8daf072103079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b2103111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2210318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa08401742103230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de121035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a62103bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c2103cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d175462103d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d4248282103ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a5f6702c00fb275522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb5368ae')

        script, script_len = make_cbuffer('001425c3a6fcf3bc212b99f4a087e079c4d018c4a8a8')
        contract_script, contract_script_len = make_cbuffer('00'*federation_script_len)
        self.assertEqual(wally_elements_pegin_contract_script_from_bytes(federation_script, federation_script_len,
                                                                         script, script_len,
                                                                         0, contract_script, contract_script_len)[0], WALLY_OK)
        self.assertEqual(expected, contract_script)


if __name__ == '__main__':
    _, val = wally_is_elements_build()
    if val != 0:
        unittest.main()
