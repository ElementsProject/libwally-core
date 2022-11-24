import assert from 'assert'

import * as wally from './index.js'
import { bytesToHex, hexToBytes } from './index.js'
import {
    WALLY_NETWORK_BITCOIN_MAINNET, WALLY_ADDRESS_VERSION_WIF_MAINNET, WALLY_WIF_FLAG_COMPRESSED,
    BIP32_FLAG_KEY_PUBLIC, BIP32_INITIAL_HARDENED_CHILD,
} from './index.js'

// Test simple invocation, with a return code only and no destination pointer
wally.hex_verify('00') // should not throw
assert.throws(_ => wally.hex_verify('001'), 'WALLY_EINVAL')

// Test string destination pointer
assert.equal(wally.bip39_get_word(null, 10), 'access')

// Test string argument and a string destination pointer
assert.equal(bytesToHex(wally.address_to_scriptpubkey("1EMBaSSyxMQPV2fmUsdB7mMfMoocgfiMNw", WALLY_NETWORK_BITCOIN_MAINNET)),
    '76a914926ac8843cbca0ee59aa857188324d6d5b76c1c688ac')

// Test bytes buffer argument
assert.equal(wally.bip39_mnemonic_from_bytes(null, hexToBytes('b5bb9d8014a0f9b1d61e21e796d78dcc')),
    'remember table gas citizen auto suggest flash service travel repeat toddler occur')

// Test `written` pointer as the return value
assert.equal(wally.wif_is_uncompressed("L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6"), 0)
assert.equal(wally.wif_is_uncompressed("5Kdc3UAwGmHHuj6fQD1LDmKR6J3SwYyFWyHgxKAZ2cKRzVCRETY"), 1)

assert.equal(wally.wif_from_bytes(hexToBytes('b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'), WALLY_ADDRESS_VERSION_WIF_MAINNET, WALLY_WIF_FLAG_COMPRESSED),
    'L3JyYy6eC7JRohrc1XH1Y7caP966K5rbhFH7JEjpygufxTzEqR1Q')

// Test the use of returned opaque references
const txhex = '020000000001015720d1aa6ac6bed17730b5e852c82191b73d1bd14cae6d7ccb8a4deab03081390000000000fdffffff018e5a0f00000000001976a914422e4acaed40191100fc4d13632574b62ee2ca2588ac0247304402203371fbdb07d9fefbf9e0f6d31700979297f36a871962a5c601e3495874dbeeaa022071e323524a4aa2d849a1295430d68e8e2e46fc99662d1b8e46435ffb47a699ca01210381722a93622de13f6848663f854a896d5910aadf5461937bcf3f02464cd36a0cd1860b00'
const tx1 = wally.tx_from_hex(txhex, null)
assert.equal(wally.tx_get_witness_count(tx1), 1)
assert.equal(bytesToHex(wally.tx_get_txid(tx1)), "bc54928ad07bbe606ec27c8f9af9266b5c73cf01219f5cc545f849135c44bc90")

// Test bigint return value
assert.equal(wally.tx_get_total_output_satoshi(tx1), 1006222n)
wally.tx_free(tx1)

// Test bigint argument
assert.equal(wally.varint_get_length(100000n), 5)

// Test base58 roundtrip for bip32 keys
const hdkey_bs58 = 'xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU'
const hdkey = wally.bip32_key_from_base58(hdkey_bs58)
assert.equal(wally.bip32_key_to_base58(hdkey, BIP32_FLAG_KEY_PUBLIC), hdkey_bs58)

// Test the use of integer array arguments
const hdkey_child = wally.bip32_key_from_parent_path(hdkey, [7, 0], BIP32_FLAG_KEY_PUBLIC)
assert.equal(wally.bip32_key_to_base58(hdkey_child, BIP32_FLAG_KEY_PUBLIC),
    'xpub6EsQ4V9aBsTisnb7dmpDC14Z6uHQEUKXSio6HdoxRuWsLBn8XGVFMVXEBad5Ey2pnG3B28oeTLeYscNcKi55XEi6Ru1pPSjHeeHoAic8x5B')

wally.bip32_key_free(hdkey)
wally.bip32_key_free(hdkey_child)

// Test varlen buffers (https://wally.readthedocs.io/en/latest/conventions/#variable-length-output-buffers)
const longhex = Array(200).join('00')
const bytes = wally.hex_to_bytes(longhex)
assert.equal(bytesToHex(bytes), longhex)

const vbytes = wally.varbuff_to_bytes(hexToBytes('133337'));
assert.equal(bytesToHex(vbytes), '03133337')

// Test uint32 array as an argument and return value
const keypaths = wally.map_keypath_public_key_init(1)
    , dummy_pubkey = wally.hex_to_bytes('038575eb35e18fb168a913d8b49af50204f4f73627f6f7884f1be11e354664de8b')
    , dummy_fingerprint = wally.hex_to_bytes('00112233')
    , dummy_path = [0, 50, 127, 128, 1024, BIP32_INITIAL_HARDENED_CHILD, BIP32_INITIAL_HARDENED_CHILD+1]

wally.map_keypath_add(keypaths, dummy_pubkey, dummy_fingerprint, dummy_path)
assert.equal(wally.map_keypath_get_item_path(keypaths, 0).join(','), dummy_path.join(','))

// Test output buffers with a user-specified length (scrypt is the only instance of this)
const try_scrypt = size => wally.scrypt(Buffer.from("password"), Buffer.from("NaCl"), 1024, 8, 16, size)
assert(wally.bytesToHex(try_scrypt(32)), 'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162')
assert(wally.bytesToHex(try_scrypt(64)), 'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640')

console.log('Tests passed.')