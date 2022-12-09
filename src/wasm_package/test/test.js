import test from 'test'

import assert from 'assert'

import wally from '../src/index.js'
import { toWallyMap, fromWallyMap } from '../src/util.js'

test('Use of all the various data types for arguments and return values', t => {
    test('simple invocation, with a return code only and no destination pointer', () => {
        wally.hex_verify('00') // should not throw
        assert.throws(_ => wally.hex_verify('001'), 'WALLY_EINVAL')
    })

    test('string destination pointer', () => {
        assert.equal(wally.bip39_get_word(null, 10), 'access')
    })

    test('string argument and a string destination pointer', () => {
        assert.equal(wally.address_to_scriptpubkey("1EMBaSSyxMQPV2fmUsdB7mMfMoocgfiMNw", wally.WALLY_NETWORK_BITCOIN_MAINNET).toString('hex'),
            '76a914926ac8843cbca0ee59aa857188324d6d5b76c1c688ac')
    })

    test('bytes buffer argument', () => {
        assert.equal(wally.bip39_mnemonic_from_bytes(null, Buffer.from('b5bb9d8014a0f9b1d61e21e796d78dcc', 'hex')),
            'remember table gas citizen auto suggest flash service travel repeat toddler occur')
    })

    test('`written` pointer as the return value', () => {
        assert.equal(wally.wif_is_uncompressed("L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6"), 0)
        assert.equal(wally.wif_is_uncompressed("5Kdc3UAwGmHHuj6fQD1LDmKR6J3SwYyFWyHgxKAZ2cKRzVCRETY"), 1)

        assert.equal(wally.wif_from_bytes(Buffer.from('b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c', 'hex'), wally.WALLY_ADDRESS_VERSION_WIF_MAINNET, wally.WALLY_WIF_FLAG_COMPRESSED),
            'L3JyYy6eC7JRohrc1XH1Y7caP966K5rbhFH7JEjpygufxTzEqR1Q')
    })

    test('the use of returned opaque references', () => {
        const txhex = '020000000001015720d1aa6ac6bed17730b5e852c82191b73d1bd14cae6d7ccb8a4deab03081390000000000fdffffff018e5a0f00000000001976a914422e4acaed40191100fc4d13632574b62ee2ca2588ac0247304402203371fbdb07d9fefbf9e0f6d31700979297f36a871962a5c601e3495874dbeeaa022071e323524a4aa2d849a1295430d68e8e2e46fc99662d1b8e46435ffb47a699ca01210381722a93622de13f6848663f854a896d5910aadf5461937bcf3f02464cd36a0cd1860b00'
        const tx = wally.tx_from_hex(txhex, 0)
        assert.equal(wally.tx_get_witness_count(tx), 1)
        assert.equal(wally.tx_get_txid(tx).toString('hex'), "bc54928ad07bbe606ec27c8f9af9266b5c73cf01219f5cc545f849135c44bc90")
        wally.tx_free(tx)
    })

    test('bigint return value', () => {
        const tx = wally.tx_from_hex('020000000001015720d1aa6ac6bed17730b5e852c82191b73d1bd14cae6d7ccb8a4deab03081390000000000fdffffff018e5a0f00000000001976a914422e4acaed40191100fc4d13632574b62ee2ca2588ac0247304402203371fbdb07d9fefbf9e0f6d31700979297f36a871962a5c601e3495874dbeeaa022071e323524a4aa2d849a1295430d68e8e2e46fc99662d1b8e46435ffb47a699ca01210381722a93622de13f6848663f854a896d5910aadf5461937bcf3f02464cd36a0cd1860b00', 0)
        assert.equal(wally.tx_get_total_output_satoshi(tx), 1006222n)
        wally.tx_free(tx)
    })

    test('bigint arguments', () => {
        assert.equal(wally.varint_get_length(100000n), 5)
    })

    test('base58 roundtrip for bip32 keys', () => {
        const hdkey_bs58 = 'xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU'
        const hdkey = wally.bip32_key_from_base58(hdkey_bs58)
        assert.equal(wally.bip32_key_to_base58(hdkey, wally.BIP32_FLAG_KEY_PUBLIC), hdkey_bs58)
        wally.bip32_key_free(hdkey)
    })

    test('the use of integer array arguments', () => {
        const hdkey = wally.bip32_key_from_base58('xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU')
        const hdkey_child = wally.bip32_key_from_parent_path(hdkey, [7, 0], wally.BIP32_FLAG_KEY_PUBLIC)
        assert.equal(wally.bip32_key_to_base58(hdkey_child, wally.BIP32_FLAG_KEY_PUBLIC),
            'xpub6EsQ4V9aBsTisnb7dmpDC14Z6uHQEUKXSio6HdoxRuWsLBn8XGVFMVXEBad5Ey2pnG3B28oeTLeYscNcKi55XEi6Ru1pPSjHeeHoAic8x5B')

        wally.bip32_key_free(hdkey)
        wally.bip32_key_free(hdkey_child)
    })

    test('varlen buffers (https://wally.readthedocs.io/en/latest/conventions/#variable-length-output-buffers)', () => {
        const longhex = Array(200).join('00')
        const bytes = wally.hex_to_bytes(longhex)
        assert.equal(bytes.toString('hex'), longhex)

        const vbytes = wally.varbuff_to_bytes(Buffer.from('133337', 'hex'));
        assert.equal(vbytes.toString('hex'), '03133337')
    })

    test('uint32 array as an argument and return value', () => {
        const keypaths = wally.map_keypath_public_key_init(1)
            , dummy_pubkey = wally.hex_to_bytes('038575eb35e18fb168a913d8b49af50204f4f73627f6f7884f1be11e354664de8b')
            , dummy_fingerprint = wally.hex_to_bytes('00112233')
            , dummy_path = [0, 50, 127, 128, 1024, wally.BIP32_INITIAL_HARDENED_CHILD, wally.BIP32_INITIAL_HARDENED_CHILD + 1]

        wally.map_keypath_add(keypaths, dummy_pubkey, dummy_fingerprint, dummy_path)
        assert.equal(wally.map_keypath_get_item_path(keypaths, 0).join(','), dummy_path.join(','))
        wally.map_free(keypaths)
    })

    test('output buffers with a user-specified length (scrypt is the only instance of this)', () => {
        const try_scrypt = size => wally.scrypt(Buffer.from("password"), Buffer.from("NaCl"), 1024, 8, 16, size)
        assert.equal(try_scrypt(32).toString('hex'), 'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162')
        assert.equal(try_scrypt(64).toString('hex'), 'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640')
    })
})

test('JS<->wally map conversion', () => {
    let m1, m2
    const js_map = new Map([
        [0, Buffer.from('zero')],
        [1, Buffer.from('one')],
        ['k1', Buffer.from('v1')],
        ['k2', Buffer.from('v2')],
    ])
    assert.deepEqual(fromWallyMap(m1 = toWallyMap(js_map)), js_map)
    // works with plain objects and string values (auto-converted to a Map of Buffer values)
    assert.deepEqual(fromWallyMap(m2 = toWallyMap({ 'foo': 'bar' })), new Map([['foo', Buffer.from('bar')]]))
    wally.map_free(m1)
    wally.map_free(m2)
})

test('Functions that depend on a JS length function', t => {
    test('base58 conversion', () => {
        assert.equal(wally.base58_to_bytes('1EMBaSSyxMQPV2fmUsdB7mMfMoocgfiMNw', 0).toString('hex'), '00926ac8843cbca0ee59aa857188324d6d5b76c1c6f0bcc3b0')
        assert.equal(wally.base58_n_to_bytes('1EMBaSSyxMQPV2fmUsdB7mMfMoocgfiMNw', 34, 0).toString('hex'), '00926ac8843cbca0ee59aa857188324d6d5b76c1c6f0bcc3b0')
    })

    test('AES', () => {
        assert.equal(wally.aes(Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex'), Buffer.from('ae2d8a571e03ac9c9eb76fac45af8e51', 'hex'), wally.AES_FLAG_ENCRYPT).toString('hex'), 'f5d3d58503b9699de785895a96fdbaaf')
        assert.equal(wally.aes(Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex'), Buffer.from('f5d3d58503b9699de785895a96fdbaaf', 'hex'), wally.AES_FLAG_DECRYPT).toString('hex'), 'ae2d8a571e03ac9c9eb76fac45af8e51')
        assert.equal(wally.aes_cbc(Buffer.from('b6bb953ba709b450bfba14f8e8c6b423', 'hex'), Buffer.from('1d3793f6b9ceb8d1c70726bc890f1f10', 'hex'), Buffer.from('212c4fab8ad5a7de2361ebe033cb', 'hex'), wally.AES_FLAG_ENCRYPT).toString('hex'), '9a8a46a2e63518933dd3ad846b04dc08')
        assert.equal(wally.aes_cbc(Buffer.from('b6bb953ba709b450bfba14f8e8c6b423', 'hex'), Buffer.from('1d3793f6b9ceb8d1c70726bc890f1f10', 'hex'), Buffer.from('9a8a46a2e63518933dd3ad846b04dc08', 'hex'), wally.AES_FLAG_DECRYPT).toString('hex'), '212c4fab8ad5a7de2361ebe033cb')
    })

    test('WIF conversion', () => {
        assert.equal(wally.wif_to_public_key('KxDQjJwvLdNNGhsipGgmceWaPjRndZuaQB9B2tgdHsw5sQ8Rtqje', 0x80).toString('hex'), '02fcba7ecf41bc7e1be4ee122d9d22e3333671eb0a3a87b5cdf099d59874e1940f') // compressed
        assert.equal(wally.wif_to_public_key('5J3MnPC5qQCBiAiQ4uwmzvMkN1Yu2VJMFmSR2LQvzHyfG3aFeWg', 0x80).toString('hex'), '04fcba7ecf41bc7e1be4ee122d9d22e3333671eb0a3a87b5cdf099d59874e1940f6e51e74615a5de78c420d41a1daec0d79eb9fa9206f7bb539104d42c9a0d685e') // same key, uncompressed
    })

    // Utility function for the tests below, repeat `s` `n` times
    const r = (s, n) => Array(n + 1).join(s)

    test('multisig scripts', () => {
        const PK3 = Buffer.from(r('11', 33 * 3), 'hex') // Fake three compressed pubkeys
            , RS_1of2 = Buffer.from('5121' + r('11', 33) + '21' + r('11', 33) + '52ae', 'hex') // Fake 1of2 redeem script
            , SIG = Buffer.from(r('11', 64), 'hex') // Fake sig
        assert.equal(wally.scriptpubkey_multisig_from_bytes(PK3, 2, 0).toString('hex'),
            '52' + r('21' + r('11', 33), 3) + '53ae')
        assert.equal(wally.scriptsig_multisig_from_bytes(RS_1of2, SIG, [0x01], 0).toString('hex'),
            '00' + '4730440220' + r('11', 32) + '0220' + r('11', 32) + '01475121' + r('11', 33) + '21' + r('11', 33) + '52ae')
    })

    test('format_bitcoin_message', () => {
        const MSG_PREFIX_HEX = Buffer.from('\x18Bitcoin Signed Message:\n').toString('hex')
        const test_msg = (msg, varint_hex) =>
            assert.equal(wally.format_bitcoin_message(msg, 0).toString('hex'), MSG_PREFIX_HEX + varint_hex + msg.toString('hex'))
        test_msg(Buffer.from('aaa'), '03')
        test_msg(Buffer.from(r('a', 253)), 'fdfd00')
        assert.equal(wally.format_bitcoin_message(Buffer.from('a'), wally.BITCOIN_MESSAGE_FLAG_HASH).length, wally.SHA256_LEN)
    })

    test('script_push_from_bytes', () => {
        const test_script_push = (data, prefix_hex) =>
            assert.equal(wally.script_push_from_bytes(data, 0).toString('hex'), prefix_hex + data.toString('hex'))
        test_script_push(Buffer.from(r('00', 75), 'hex'), '4b')
        test_script_push(Buffer.from(r('00', 76), 'hex'), '4c4c')
        test_script_push(Buffer.from(r('00', 255), 'hex'), '4cff')
        test_script_push(Buffer.from(r('00', 256), 'hex'), '4d0001')
        assert.equal(wally.script_push_from_bytes(Buffer.from('foo'), wally.WALLY_SCRIPT_HASH160).length, wally.HASH160_LEN + 1)
        assert.equal(wally.script_push_from_bytes(Buffer.from('bar'), wally.WALLY_SCRIPT_SHA256).length, wally.SHA256_LEN + 1)
    })
})
