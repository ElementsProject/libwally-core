import assert from 'assert'

import * as Wally from './index.js'
import { bytesToHex, hexToBytes } from './index.js'
import {
    WALLY_NETWORK_BITCOIN_MAINNET, WALLY_ADDRESS_VERSION_WIF_MAINNET, WALLY_WIF_FLAG_COMPRESSED,
    BIP32_FLAG_KEY_PUBLIC,
} from './index.js'

assert.equal(Wally.wally_hex_verify('00'), true)
assert.throws(_ => Wally.wally_hex_verify('001'), 'WALLY_EINVAL')

assert.equal(Wally.bip39_get_word(null, 10), 'access')

assert.equal(bytesToHex(Wally.wally_address_to_scriptpubkey("1EMBaSSyxMQPV2fmUsdB7mMfMoocgfiMNw", WALLY_NETWORK_BITCOIN_MAINNET)),
    '76a914926ac8843cbca0ee59aa857188324d6d5b76c1c688ac')

assert.equal(Wally.bip39_mnemonic_from_bytes(null, hexToBytes('b5bb9d8014a0f9b1d61e21e796d78dcc')),
    'remember table gas citizen auto suggest flash service travel repeat toddler occur')

assert.equal(Wally.wally_wif_is_uncompressed("L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6"), 0)
assert.equal(Wally.wally_wif_is_uncompressed("5Kdc3UAwGmHHuj6fQD1LDmKR6J3SwYyFWyHgxKAZ2cKRzVCRETY"), 1)

assert.equal(Wally.wally_wif_from_bytes(hexToBytes('b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'), WALLY_ADDRESS_VERSION_WIF_MAINNET, WALLY_WIF_FLAG_COMPRESSED),
    'L3JyYy6eC7JRohrc1XH1Y7caP966K5rbhFH7JEjpygufxTzEqR1Q')

const txhex = '020000000001015720d1aa6ac6bed17730b5e852c82191b73d1bd14cae6d7ccb8a4deab03081390000000000fdffffff018e5a0f00000000001976a914422e4acaed40191100fc4d13632574b62ee2ca2588ac0247304402203371fbdb07d9fefbf9e0f6d31700979297f36a871962a5c601e3495874dbeeaa022071e323524a4aa2d849a1295430d68e8e2e46fc99662d1b8e46435ffb47a699ca01210381722a93622de13f6848663f854a896d5910aadf5461937bcf3f02464cd36a0cd1860b00'
const tx1 = Wally.wally_tx_from_hex(txhex, null)
const tx2 = Wally.wally_tx_from_bytes(hexToBytes(txhex), null)
assert.equal(Wally.wally_tx_get_witness_count(tx1), 1)
assert.equal(Wally.wally_tx_get_witness_count(tx2), 1)
assert.equal(bytesToHex(Wally.wally_tx_get_txid(tx1)), bytesToHex(Wally.wally_tx_get_txid(tx2)))
Wally.wally_tx_free(tx1)
Wally.wally_tx_free(tx2)

// BIP 32
// Tests the use of Uint32Array arguments

const hdkey_bs58 = 'xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU'
const hdkey = Wally.bip32_key_from_base58(hdkey_bs58)
assert.equal(Wally.bip32_key_to_base58(hdkey, BIP32_FLAG_KEY_PUBLIC), hdkey_bs58)

const hdkey_child = Wally.bip32_key_from_parent_path(hdkey, [7, 0], BIP32_FLAG_KEY_PUBLIC)
assert.equal(Wally.bip32_key_to_base58(hdkey_child, BIP32_FLAG_KEY_PUBLIC),
    'xpub6EsQ4V9aBsTisnb7dmpDC14Z6uHQEUKXSio6HdoxRuWsLBn8XGVFMVXEBad5Ey2pnG3B28oeTLeYscNcKi55XEi6Ru1pPSjHeeHoAic8x5B')

Wally.bip32_key_free(hdkey)
Wally.bip32_key_free(hdkey_child)


console.log('Tests passed.')