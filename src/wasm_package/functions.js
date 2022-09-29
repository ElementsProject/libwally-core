import { wrap, types as T } from './core.js'

import { WALLY_TXHASH_LEN  } from './const.js'

export const wally_address_to_scriptpubkey = wrap('wally_address_to_scriptpubkey', [
    T.String,
    T.Int32,
    T.DestPtrVarLen(100),
])


export const wally_wif_is_uncompressed = wrap('wally_wif_is_uncompressed', [
    T.String,
    T.DestPtr(T.Int32)
])

export const wally_wif_from_bytes = wrap('wally_wif_from_bytes', [
    T.Bytes, // private key
    T.Int32, // prefix
    T.Int32, // flags
    T.DestPtrPtr(T.String)
])

export const bip39_get_word = wrap('bip39_get_word', [
    T.OpaqueRef,
    T.Int32,
    T.DestPtrPtr(T.String)
])
export const bip39_mnemonic_from_bytes = wrap('bip39_mnemonic_from_bytes', [
    T.OpaqueRef,
    T.Bytes,
    T.DestPtrPtr(T.String),
])

export const wally_hex_verify = wrap('wally_hex_verify', [T.String])


export const wally_tx_from_bytes = wrap('wally_tx_from_bytes', [
    T.Bytes,
    T.Int32,
    T.DestPtrPtr(T.OpaqueRef),
])
export const wally_tx_from_hex = wrap('wally_tx_from_hex', [
    T.String,
    T.Int32,
    T.DestPtrPtr(T.OpaqueRef),
])

export const wally_tx_get_witness_count = wrap('wally_tx_get_witness_count', [
    T.OpaqueRef,
    T.DestPtr(T.Int32),
])

export const wally_tx_get_txid = wrap('wally_tx_get_txid', [
    T.OpaqueRef,
    T.DestPtrSized(WALLY_TXHASH_LEN),
])

export const wally_free_string = wrap('wally_free_string', [T.OpaqueRef])

export const wally_tx_free = wrap('wally_tx_free', [T.OpaqueRef])

export const bip32_key_from_base58 = wrap('bip32_key_from_base58_alloc', [
    T.String,
    T.DestPtrPtr(T.OpaqueRef),
])

export const bip32_key_from_parent_path = wrap('bip32_key_from_parent_path_alloc', [
    T.OpaqueRef,
    T.Uint32Array,
    T.Int32,
    T.DestPtrPtr(T.OpaqueRef),
])

export const bip32_key_to_base58 = wrap('bip32_key_to_base58', [
    T.OpaqueRef,
    T.Int32,
    T.DestPtrPtr(T.String),
])

export const bip32_key_free = wrap('bip32_key_free', [
    T.OpaqueRef,
])
