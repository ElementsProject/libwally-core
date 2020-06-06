from ctypes import *
from binascii import hexlify, unhexlify
from os.path import isfile, abspath
from os import urandom
import platform
import sys

# Allow to run from any sub dir
SO_EXT = 'dylib' if platform.system() == 'Darwin' else 'dll' if platform.system() == 'Windows' else 'so'
for depth in [0, 1, 2]:
    root_dir = '../' * depth
    if isfile(root_dir + 'src/.libs/libwallycore.' + SO_EXT):
        break

if platform.system() == 'Darwin':
    root_dir = abspath(root_dir) + '/'

libwally = CDLL(root_dir + 'src/.libs/libwallycore.' + SO_EXT)

wally_free_string = libwally.wally_free_string
wally_free_string.restype, wally_free_string.argtypes = None, [c_char_p]

WALLY_OK, WALLY_ERROR, WALLY_EINVAL, WALLY_ENOMEM = 0, -1, -2, -3

_malloc_fn_t = CFUNCTYPE(c_void_p, c_ulong)
_free_fn_t = CFUNCTYPE(c_void_p)
_bzero_fn_t = CFUNCTYPE(c_void_p, c_ulong)
_ec_nonce_fn_t = CFUNCTYPE(c_int, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_uint)

class operations(Structure):
    _fields_ = [('malloc_fn', _malloc_fn_t),
                ('free_fn', _free_fn_t),
                ('bzero_fn', _bzero_fn_t),
                ('ec_nonce_fn', _ec_nonce_fn_t)]

class ext_key(Structure):
    _fields_ = [('chain_code', c_ubyte * 32),
                ('parent160', c_ubyte * 20),
                ('depth', c_ubyte),
                ('pad1', c_ubyte * 10),
                ('priv_key', c_ubyte * 33),
                ('child_num', c_uint),
                ('hash160', c_ubyte * 20),
                ('version', c_uint),
                ('pad2', c_ubyte * 3),
                ('pub_key', c_ubyte * 33),
                ('pub_key_tweak_sum', c_ubyte * 32)]

class wally_descriptor_address_item(Structure):
    _fields_ = [('child_num', c_uint),
                ('address', c_char_p),
                ('address_len', c_ulong)]

class wally_descriptor_addresses(Structure):
    _fields_ = [('items',  POINTER(wally_descriptor_address_item)),
                ('num_items', c_ulong)]

# Sentinel classes for returning output parameters
class c_char_p_p_class(object):
    pass
c_char_p_p = c_char_p_p_class()
class c_ulong_p_class(object):
    pass
c_ulong_p = c_ulong_p_class()

# ctypes is missing this for some reason
c_uint_p = POINTER(c_uint)

class wally_tx_witness_item(Structure):
    _fields_ = [('witness', c_void_p),
                ('len', c_ulong)]

class wally_tx_witness_stack(Structure):
    _fields_ = [('items', POINTER(wally_tx_witness_item)),
                ('num_items', c_ulong),
                ('items_allocation_len', c_ulong)]

class wally_tx_input(Structure):
    _fields_ = [('txhash', c_ubyte * 32),
                ('index', c_uint),
                ('sequence', c_uint),
                ('script', c_void_p),
                ('script_len', c_ulong),
                ('witness',  POINTER(wally_tx_witness_stack)),
                ('features', c_ubyte),
                ('blinding_nonce', c_ubyte * 32),
                ('entropy', c_ubyte * 32),
                ('issuance_amount', c_void_p),
                ('issuance_amount_len', c_ulong),
                ('inflation_keys', c_void_p),
                ('inflation_keys_len', c_ulong),
                ('issuance_amount_rangeproof', c_void_p),
                ('issuance_amount_rangeproof_len', c_ulong),
                ('inflation_keys_rangeproof', c_void_p),
                ('inflation_keys_rangeproof_len', c_ulong),
                ('pegin_witness', POINTER(wally_tx_witness_stack))]

class wally_tx_output(Structure):
    _fields_ = [('satoshi', c_ulonglong),
                ('script', c_void_p),
                ('script_len', c_ulong),
                ('features', c_ubyte),
                ('asset', c_void_p),
                ('asset_len', c_ulong),
                ('value', c_void_p),
                ('value_len', c_ulong),
                ('nonce', c_void_p),
                ('nonce_len', c_ulong),
                ('surjectionproof', c_void_p),
                ('surjectionproof_len', c_ulong),
                ('rangeproof', c_void_p),
                ('rangeproof_len', c_ulong)]

class wally_tx(Structure):
    _fields_ = [('version', c_uint),
                ('locktime', c_uint),
                ('inputs', POINTER(wally_tx_input)),
                ('num_inputs', c_ulong),
                ('inputs_allocation_len', c_ulong),
                ('outputs', POINTER(wally_tx_output)),
                ('num_outputs', c_ulong),
                ('outputs_allocation_len', c_ulong),]

class key_origin_info(Structure):
    _fields_ = [('fingerprint', c_ubyte * 4),
                ('items', POINTER(c_ulong)),
                ('path_len', c_ulong)]

class keypath_item(Structure):
    _fields_ = [('pubkey', c_ubyte * 65),
                ('origin', key_origin_info)]

class keypath_map(Structure):
    _fields_ = [('items', POINTER(keypath_item)),
                ('num_items', c_ulong),
                ('items_allocation_len', c_ulong)]

class partial_sigs_item(Structure):
    _fields_ = [('pubkey', c_ubyte * 65),
                ('sig', c_void_p),
                ('sig_len', c_ulong)]

class partial_sigs_map(Structure):
    _fields_ = [('items', POINTER(partial_sigs_item)),
                ('num_items', c_ulong),
                ('items_allocation_len', c_ulong)]

class unknowns_item(Structure):
    _fields_ = [('key', c_void_p),
                ('key_len', c_ulong),
                ('value', c_void_p),
                ('value_len', c_ulong)]

class unknowns_map(Structure):
    _fields_ = [('items', POINTER(unknowns_item)),
                ('num_items', c_ulong),
                ('items_allocation_len', c_ulong)]

class wally_psbt_input(Structure):
    _fields_ = [('non_witness_utxo', POINTER(wally_tx)),
                ('witness_utxo', POINTER(wally_tx_output)),
                ('redeem_script', c_void_p),
                ('redeem_script_len', c_ulong),
                ('witness_script', c_void_p),
                ('witness_script_len', c_ulong),
                ('final_script_sig', c_void_p),
                ('final_script_sig_len', c_ulong),
                ('final_witness', POINTER(wally_tx_witness_stack)),
                ('keypaths', POINTER(keypath_map)),
                ('partial_sigs', POINTER(partial_sigs_map)),
                ('unknowns', POINTER(unknowns_map)),
                ('sighash_type', c_ulong)]

class wally_psbt_output(Structure):
    _fields_ = [('redeem_script', c_void_p),
                ('redeem_script_len', c_ulong),
                ('witness_script', c_void_p),
                ('witness_script_len', c_ulong),
                ('keypaths', POINTER(keypath_map)),
                ('unknowns', POINTER(unknowns_map))]

class wally_psbt(Structure):
    _fields_ = [('tx', POINTER(wally_tx)),
                ('inputs', POINTER(wally_psbt_input)),
                ('num_inputs', c_ulong),
                ('inputs_allocation_len', c_ulong),
                ('outputs', POINTER(wally_psbt_output)),
                ('num_outputs', c_ulong),
                ('outputs_allocation_len', c_ulong),
                ('unknowns', POINTER(unknowns_map))]

for f in (
    ('wally_init', c_int, [c_uint]),
    ('wally_cleanup', c_int, [c_uint]),
    ('wally_is_elements_build', c_int, [c_ulong_p]),
    ('wordlist_init', c_void_p, [c_char_p]),
    ('wordlist_lookup_word', c_ulong, [c_void_p, c_char_p]),
    ('wordlist_lookup_index', c_char_p, [c_void_p, c_ulong]),
    ('wordlist_free', None, [c_void_p]),
    ('mnemonic_from_bytes', c_char_p, [c_void_p, c_void_p, c_ulong]),
    ('mnemonic_to_bytes', c_int, [c_void_p, c_char_p, c_void_p, c_ulong, c_ulong_p]),
    ('wally_base58_from_bytes', c_int, [c_void_p, c_ulong, c_uint, c_char_p_p]),
    ('wally_base58_get_length', c_int, [c_char_p, c_ulong_p]),
    ('wally_base58_to_bytes', c_int, [c_char_p, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('bip32_key_free', c_int, [POINTER(ext_key)]),
    ('bip32_key_from_seed', c_int, [c_void_p, c_ulong, c_uint, c_uint, POINTER(ext_key)]),
    ('bip32_key_serialize', c_int, [POINTER(ext_key), c_uint, c_void_p, c_ulong]),
    ('bip32_key_unserialize', c_int, [c_void_p, c_uint, POINTER(ext_key)]),
    ('bip32_key_from_parent', c_int, [c_void_p, c_uint, c_uint, POINTER(ext_key)]),
    ('bip32_key_from_parent_path', c_int, [c_void_p, c_uint_p, c_ulong, c_uint, POINTER(ext_key)]),
    ('bip32_key_with_tweak_from_parent_path', c_int, [POINTER(ext_key), c_uint_p, c_ulong, c_uint, POINTER(ext_key)]),
    ('bip32_key_to_base58', c_int, [POINTER(ext_key), c_uint, c_char_p_p]),
    ('bip32_key_from_base58', c_int, [c_char_p, POINTER(ext_key)]),
    ('bip32_key_from_base58_alloc', c_int, [c_char_p, POINTER(POINTER(ext_key))]),
    ('bip32_key_strip_private_key', c_int, [POINTER(ext_key)]),
    ('bip32_key_get_fingerprint', c_int, [POINTER(ext_key), c_void_p, c_ulong]),
    ('bip38_raw_from_private_key', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_void_p, c_ulong]),
    ('bip38_from_private_key', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_char_p_p]),
    ('bip38_to_private_key', c_int, [c_char_p, c_void_p, c_ulong, c_uint, c_void_p, c_ulong]),
    ('bip38_raw_to_private_key', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_void_p, c_ulong]),
    ('bip38_raw_get_flags', c_int, [c_void_p, c_ulong, c_ulong_p]),
    ('bip38_get_flags', c_int, [c_char_p, c_ulong_p]),
    ('bip39_get_languages', c_int, [c_char_p_p]),
    ('bip39_get_wordlist', c_int, [c_char_p, POINTER(c_void_p)]),
    ('bip39_get_word', c_int, [c_void_p, c_ulong, c_char_p_p]),
    ('bip39_mnemonic_from_bytes', c_int, [c_void_p, c_void_p, c_ulong, c_char_p_p]),
    ('bip39_mnemonic_to_bytes', c_int, [c_void_p, c_char_p, c_void_p, c_ulong, c_ulong_p]),
    ('bip39_mnemonic_validate', c_int, [c_void_p, c_char_p]),
    ('bip39_mnemonic_to_seed', c_int, [c_char_p, c_char_p, c_void_p, c_ulong, c_ulong_p]),
    ('wally_addr_segwit_from_bytes', c_int, [c_void_p, c_ulong, c_char_p, c_uint, c_char_p_p]),
    ('wally_addr_segwit_to_bytes', c_int, [c_void_p, c_char_p, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_address_to_scriptpubkey', c_int, [c_char_p, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_scriptpubkey_to_address', c_int, [c_void_p, c_ulong, c_uint, c_char_p_p]),
    ('wally_bip32_key_to_address', c_int, [POINTER(ext_key), c_uint, c_uint, c_char_p_p]),
    ('wally_bip32_key_to_addr_segwit', c_int, [POINTER(ext_key), c_char_p, c_uint, c_char_p_p]),
    ('wally_confidential_addr_from_addr', c_int, [c_char_p, c_uint, c_void_p, c_ulong, c_char_p_p]),
    ('wally_confidential_addr_to_addr', c_int, [c_char_p, c_uint, c_char_p_p]),
    ('wally_confidential_addr_to_ec_public_key', c_int, [c_char_p, c_uint, c_void_p, c_ulong]),
    ('wally_asset_blinding_key_from_seed', c_int, [c_void_p, c_ulong, c_void_p, c_ulong]),
    ('wally_asset_blinding_key_to_ec_private_key', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong]),
    ('wally_asset_unblind', c_int, [c_char_p, c_ulong, c_char_p, c_ulong, c_char_p, c_ulong, c_char_p, c_ulong, c_char_p, c_ulong, c_char_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_ulong_p]),
    ('wally_asset_unblind_with_nonce', c_int, [c_char_p, c_ulong, c_char_p, c_ulong, c_char_p, c_ulong, c_char_p, c_ulong, c_char_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_ulong_p]),
    ('wally_asset_pak_whitelistproof', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong]),
    # ('wally_asset_pak_whitelistproof', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_ulong_p]),
    ('wally_sha256', c_int, [c_void_p, c_ulong, c_void_p, c_ulong]),
    ('wally_sha256d', c_int, [c_void_p, c_ulong, c_void_p, c_ulong]),
    ('wally_sha512', c_int, [c_void_p, c_ulong, c_void_p, c_ulong]),
    ('wally_hash160', c_int, [c_void_p, c_ulong, c_void_p, c_ulong]),
    ('wally_hex_from_bytes', c_int, [c_void_p, c_ulong, c_char_p_p]),
    ('wally_hex_to_bytes', c_int, [c_char_p, c_void_p, c_ulong, c_ulong_p]),
    ('wally_hmac_sha256', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_void_p]),
    ('wally_hmac_sha512', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_void_p]),
    ('wally_aes', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_void_p, c_ulong]),
    ('wally_aes_cbc', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_pbkdf2_hmac_sha256', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_ulong, c_void_p, c_ulong]),
    ('wally_pbkdf2_hmac_sha512', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_ulong, c_void_p, c_ulong]),
    ('wally_scrypt', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_uint, c_uint, c_void_p, c_ulong]),
    ('wally_secp_randomize', c_int, [c_void_p, c_ulong]),
    ('wally_ec_private_key_verify', c_int, [c_void_p, c_ulong]),
    ('wally_ec_public_key_verify', c_int, [c_void_p, c_ulong]),
    ('wally_ec_public_key_decompress', c_int, [c_void_p, c_ulong, c_void_p, c_ulong]),
    ('wally_ec_public_key_negate', c_int, [c_void_p, c_ulong, c_void_p, c_ulong]),
    ('wally_ec_public_key_from_private_key', c_int, [c_void_p, c_ulong, c_void_p, c_ulong]),
    ('wally_ec_sig_from_bytes', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_void_p, c_ulong]),
    ('wally_ec_sig_from_der', c_int, [c_void_p, c_ulong, c_void_p, c_ulong]),
    ('wally_ec_sig_normalize', c_int, [c_void_p, c_ulong, c_void_p, c_ulong]),
    ('wally_ec_sig_to_der', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_ulong_p]),
    ('wally_ec_sig_to_public_key', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_void_p]),
    ('wally_ec_sig_verify', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_void_p, c_ulong]),
    ('wally_ecdh', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_void_p]),
    ('wally_get_operations', c_int, [POINTER(operations)]),
    ('wally_set_operations', c_int, [POINTER(operations)]),
    ('wally_format_bitcoin_message', c_int, [c_void_p, c_ulong, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_scriptpubkey_get_type', c_int, [c_void_p, c_ulong, c_ulong_p]),
    ('wally_script_push_from_bytes', c_int, [c_void_p, c_ulong, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_scriptpubkey_op_return_from_bytes', c_int, [c_void_p, c_ulong, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_scriptpubkey_p2pkh_from_bytes', c_int, [c_void_p, c_ulong, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_scriptpubkey_p2sh_from_bytes', c_int, [c_void_p, c_ulong, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_scriptpubkey_multisig_from_bytes', c_int, [c_void_p, c_ulong, c_uint, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_scriptpubkey_csv_2of2_then_1_from_bytes', c_int, [c_void_p, c_ulong, c_uint, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_scriptpubkey_csv_2of3_then_2_from_bytes', c_int, [c_void_p, c_ulong, c_uint, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_scriptsig_p2pkh_from_der', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_ulong_p]),
    ('wally_scriptsig_p2pkh_from_sig', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_scriptsig_multisig_from_bytes', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_uint_p, c_ulong, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_elements_pegout_script_from_bytes', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_elements_pegin_contract_script_from_bytes', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_witness_program_from_bytes', c_int, [c_void_p, c_ulong, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_tx_to_hex', c_int, [POINTER(wally_tx), c_uint, c_char_p_p]),
    ('wally_tx_from_hex', c_int, [c_char_p, c_uint, POINTER(POINTER(wally_tx))]),
    ('wally_tx_to_bytes', c_int, [POINTER(wally_tx), c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_tx_from_bytes', c_int, [c_void_p, c_ulong, c_uint, POINTER(POINTER(wally_tx))]),
    ('wally_tx_init_alloc', c_int, [c_uint, c_uint, c_ulong, c_ulong, POINTER(POINTER(wally_tx))]),
    ('wally_tx_free', c_int, [POINTER(wally_tx)]),
    ('wally_tx_get_length', c_int, [POINTER(wally_tx), c_uint, c_ulong_p]),
    ('wally_tx_get_vsize', c_int, [POINTER(wally_tx), c_ulong_p]),
    ('wally_tx_get_weight', c_int, [POINTER(wally_tx), c_ulong_p]),
    ('wally_tx_vsize_from_weight', c_int, [c_ulong, c_ulong_p]),
    ('wally_tx_get_total_output_satoshi', c_int, [POINTER(wally_tx), POINTER(c_ulonglong)]),
    ('wally_tx_get_witness_count', c_int, [POINTER(wally_tx), c_ulong_p]),
    ('wally_tx_get_btc_signature_hash', c_int, [POINTER(wally_tx), c_ulong, c_void_p, c_ulong, c_ulonglong, c_uint, c_uint, c_void_p, c_ulong]),
    ('wally_tx_get_elements_signature_hash', c_int, [POINTER(wally_tx), c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_uint, c_uint, c_void_p, c_ulong]),
    ('wally_tx_witness_stack_init_alloc', c_int, [c_ulong, POINTER(POINTER(wally_tx_witness_stack))]),
    ('wally_tx_witness_stack_free', c_int, [POINTER(wally_tx_witness_stack)]),
    ('wally_tx_witness_stack_add', c_int, [POINTER(wally_tx_witness_stack), c_void_p, c_ulong]),
    ('wally_tx_witness_stack_add_dummy', c_int, [POINTER(wally_tx_witness_stack), c_uint]),
    ('wally_tx_witness_stack_set', c_int, [POINTER(wally_tx_witness_stack), c_ulong, c_void_p, c_ulong]),
    ('wally_tx_witness_stack_set_dummy', c_int, [POINTER(wally_tx_witness_stack), c_ulong, c_uint]),
    ('wally_tx_output_init_alloc', c_int, [c_ulonglong, c_void_p, c_ulong, POINTER(POINTER(wally_tx_output))]),
    ('wally_tx_output_free', c_int, [POINTER(wally_tx_output)]),
    ('wally_tx_add_output', c_int, [POINTER(wally_tx), POINTER(wally_tx_output)]),
    ('wally_tx_add_raw_output', c_int, [POINTER(wally_tx), c_ulonglong, c_void_p, c_ulong, c_uint]),
    ('wally_tx_add_elements_raw_output', c_int, [POINTER(wally_tx), c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_uint]),
    ('wally_tx_remove_output', c_int, [POINTER(wally_tx), c_ulong]),
    ('wally_tx_input_init_alloc', c_int, [c_void_p, c_ulong, c_uint, c_uint, c_void_p, c_ulong, POINTER(wally_tx_witness_stack), POINTER(POINTER(wally_tx_input))]),
    ('wally_tx_input_free', c_int, [POINTER(wally_tx_input)]),
    ('wally_tx_add_input', c_int, [POINTER(wally_tx), POINTER(wally_tx_input)]),
    ('wally_tx_add_raw_input', c_int, [POINTER(wally_tx), c_void_p, c_ulong, c_uint, c_uint, c_void_p, c_ulong, POINTER(wally_tx_witness_stack), c_uint]),
    ('wally_tx_add_elements_raw_input', c_int, [POINTER(wally_tx), c_void_p, c_ulong, c_uint, c_uint, c_void_p, c_ulong, POINTER(wally_tx_witness_stack), c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, POINTER(wally_tx_witness_stack), c_uint]),
    ('wally_tx_remove_input', c_int, [POINTER(wally_tx), c_ulong]),
    ('wally_tx_set_input_script', c_int, [POINTER(wally_tx), c_ulong, c_void_p, c_ulong]),
    ('wally_tx_set_input_witness', c_int, [POINTER(wally_tx), c_ulong, POINTER(wally_tx_witness_stack)]),
    ('wally_tx_confidential_value_from_satoshi', c_int, [c_ulonglong, c_void_p, c_ulong]),
    ('wally_wif_from_bytes', c_int, [c_void_p, c_ulong, c_uint, c_uint, c_char_p_p]),
    ('wally_wif_to_address', c_int, [c_char_p, c_uint, c_uint, c_char_p_p]),
    ('wally_wif_to_bytes', c_int, [c_char_p, c_uint, c_uint, c_void_p, c_ulong]),
    ('wally_wif_to_public_key', c_int, [c_char_p, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_wif_is_uncompressed', c_int, [c_char_p, c_ulong_p]),
    ('wally_psbt_input_init_alloc', c_int, [POINTER(wally_tx), POINTER(wally_tx_output), c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, POINTER(wally_tx_witness_stack), POINTER(keypath_map), POINTER(partial_sigs_map), POINTER(unknowns_map), c_ulong, POINTER(POINTER(wally_psbt_input))]),
    ('wally_psbt_input_free', c_int, [POINTER(wally_psbt_input)]),
    ('wally_psbt_output_init_alloc', c_int, [c_void_p, c_ulong, c_void_p, c_ulong, POINTER(keypath_map), POINTER(unknowns_map), c_ulong, POINTER(POINTER(wally_psbt_output))]),
    ('wally_psbt_output_free', c_int, [POINTER(wally_psbt_output)]),
    ('wally_psbt_init_alloc', c_int, [c_ulong, c_ulong, c_ulong, POINTER(POINTER(wally_psbt))]),
    ('wally_psbt_free', c_int, [POINTER(wally_psbt)]),
    ('wally_psbt_from_bytes', c_int, [c_void_p, c_ulong, POINTER(POINTER(wally_psbt))]),
    ('wally_psbt_to_bytes', c_int, [POINTER(wally_psbt), c_void_p, c_ulong, c_ulong_p]),
    ('wally_psbt_get_length', c_int, [POINTER(wally_psbt), c_ulong_p]),
    ('wally_psbt_from_base64', c_int, [c_char_p, POINTER(POINTER(wally_psbt))]),
    ('wally_psbt_to_base64', c_int, [POINTER(wally_psbt), c_char_p_p]),
    ('wally_psbt_set_global_tx', c_int, [POINTER(wally_psbt), POINTER(wally_tx)]),
    ('wally_combine_psbts', c_int, [POINTER(wally_psbt), c_ulong, POINTER(POINTER(wally_psbt))]),
    ('wally_sign_psbt', c_int, [POINTER(wally_psbt), c_void_p, c_ulong]),
    ('wally_finalize_psbt', c_int, [POINTER(wally_psbt)]),
    ('wally_extract_psbt', c_int, [POINTER(wally_psbt), POINTER(POINTER(wally_tx))]),
    ('wally_parse_miniscript', c_int, [c_char_p, c_void_p, c_void_p, c_ulong, c_uint, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_descriptor_to_scriptpubkey', c_int, [c_char_p, c_void_p, c_void_p, c_ulong, c_uint, c_uint, c_uint, c_uint, c_uint, c_void_p, c_ulong, c_ulong_p]),
    ('wally_descriptor_to_address', c_int, [c_char_p, c_void_p, c_void_p, c_ulong, c_uint, c_uint, c_uint, c_char_p_p]),
    ('wally_descriptor_to_addresses', c_int, [c_char_p, c_void_p, c_void_p, c_ulong, c_uint, c_uint, c_uint, c_uint, POINTER(wally_descriptor_addresses)]),
    ('wally_create_descriptor_checksum', c_int, [c_char_p, c_void_p, c_void_p, c_ulong, c_uint, c_char_p_p]),
    ):

    def bind_fn(name, res, args):
        try:
            fn = getattr(libwally, name)
            fn.restype, fn.argtypes = res, args
            return fn
        except AttributeError:
            # Internal function and 'configure --enable-export-all' not used
            return None

    def in_string_fn_wrapper(fn, pos, *args):
        if isinstance(args[pos], str):
            new_args = [a for a in args]
            new_args[pos] = utf8(new_args[pos])
            return fn(*new_args)
        return fn(*args)

    def string_fn_wrapper(fn, *args):
        # Return output string parameters directly without leaking
        p = c_char_p()
        new_args = [a for a in args] + [byref(p)]
        ret = fn(*new_args)
        ret_str = None if p.value is None else p.value.decode('utf-8')
        wally_free_string(p)
        return [ret_str, (ret, ret_str)][fn.restype is not None]

    def int_fn_wrapper(fn, *args):
        p = c_ulong()
        new_args = [a for a in args] + [byref(p)]
        ret = fn(*new_args)
        return [p.value, (ret, p.value)][fn.restype is not None]

    name, restype, argtypes = f
    is_str_fn = len(argtypes) and type(argtypes[-1]) is c_char_p_p_class
    is_int_fn = len(argtypes) and type(argtypes[-1]) is c_ulong_p_class
    in_str_pos = [i for (i, t) in enumerate(argtypes) if t == c_char_p]
    if is_str_fn:
        argtypes[-1] = POINTER(c_char_p)
    elif is_int_fn:
        argtypes[-1] = POINTER(c_ulong)
    fn = bind_fn(name, restype, argtypes)
    def mkstr(f): return lambda *args: string_fn_wrapper(f, *args)
    def mkint(f): return lambda *args: int_fn_wrapper(f, *args)
    def mkinstr(f, pos): return lambda *args: in_string_fn_wrapper(f, pos, *args)
    if is_str_fn:
        fn = mkstr(fn)
    elif is_int_fn:
        fn = mkint(fn)
    if len(in_str_pos) > 0 and fn:
        for pos in in_str_pos:
            fn = mkinstr(fn, pos)
    globals()[name] = fn

is_python3 = int(sys.version[0]) >= 3
def load_words(lang):
    kwargs = {'name': root_dir + 'src/data/wordlists/%s.txt' % lang, 'mode': 'r'}
    if is_python3:
        kwargs.update({'encoding': 'utf-8'})
        kwargs['file'] = kwargs.pop('name')
    with open(**kwargs) as f:
        words_list = [l.strip() for l in f.readlines()]
        return words_list, ' '.join(words_list)

def h(s):
    return hexlify(s)

def make_cbuffer(hex_in):
    if hex_in is None:
        return None, 0
    hex_len = len(hex_in) // 2
    return unhexlify(hex_in), hex_len

utf8 = lambda s: s
if is_python3:
    utf8 = lambda s: s.encode('utf-8')

assert wally_secp_randomize(urandom(32), 32) == WALLY_OK, 'Random init failed'

_original_ops = operations()
_new_ops = operations()
for ops in (_original_ops, _new_ops):
    assert wally_get_operations(byref(ops)) == WALLY_OK

# Disable internal tests if not available
def internal_only():
    def decorator(test_func):
        def wrapped(*args):
            if wordlist_init is None:
                print (test_func.__name__ + ' disabled, use --enable-export-all to enable ')
            else:
                return test_func(*args)
        return wrapped
    return decorator

# Support for malloc testing
_fail_malloc_at = 0
_fail_malloc_counter = 0

def _failable_malloc(size):
    global _fail_malloc_counter
    _fail_malloc_counter += 1
    if _fail_malloc_counter == _fail_malloc_at:
        return None
    return _original_ops.malloc_fn(size)

_new_ops.malloc_fn = _malloc_fn_t(_failable_malloc)

def malloc_fail(failures):
    def decorator(test_func):
        def wrapped(*args):
            global _fail_malloc_at, _fail_malloc_counter
            for fail_at in failures:
                _fail_malloc_at, _fail_malloc_counter = fail_at, 0
                test_func(*args)
                _fail_malloc_at, _fail_malloc_counter = 0, 0
        return wrapped
    return decorator

# Support for signing testing
_fake_ec_nonce = None

def set_fake_ec_nonce(nonce):
    global _fake_ec_nonce
    _fake_ec_nonce = nonce

def _fake_ec_nonce_fn(nonce32, msg32, key32, algo16, data, attempt):
    global _fake_ec_nonce
    if _fake_ec_nonce is not None:
        memmove(nonce32, _fake_ec_nonce, 32)
        return 1
    return _original_ops.ec_nonce_fn(nonce32, msg32, key32, algo16, data, attempt)

_new_ops.ec_nonce_fn = _ec_nonce_fn_t(_fake_ec_nonce_fn)

assert wally_set_operations(byref(_new_ops)) == WALLY_OK
