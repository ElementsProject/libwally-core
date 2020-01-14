# Changes

## Version 0.7.7

- Expose wally_psbt_get_length
- Add wally_scriptpubkey_to_address
- Return written bytes in asset_pak_whitelistproof
- Elements bug fixes

## Version 0.7.6

- Add flag to sort multisig keys (BIP67)
- Add bip32_key_get_fingerprint
- Add Liquid developer guide
- Add liquid support to address_to_scriptpubkey

## Version 0.7.5

- Add support for P2PKH, P2SH-P2WPKH, P2WPKH address derivation from BIP32 key
- Add support for P2KH and P2SH address parsing
- Add support for PSBT
- Add support for blech32
- Add support for pegin and pegout
- Bug fixing, build updates and improvements

## Version 0.7.4

- Add support for recoverable signatures
- Generalize Elements function to use external nonces
- Expose blinding key functions to js wrapper
- doc improvement and bugs fixing

## Version 0.7.3

- Exposed ECDH, added py3.7 x86_64 linux wheels to released artifacts, updated
  JS bindings to support latest nodejs, doc typos and bug fixing.

## Version 0.7.2

- API change of wally_tx_to_bytes and wally_tx_to_hex to not accept
  WALLY_TX_FLAG_USE_ELEMENTS bit set in flags. You should remove such flag when
  upgrading. This change affects elements transactions only.

## Version 0.6.5

- Invalid bech32 addresses may have caused an out of bounds read. Thanks to
  Christian Reitter and Dr. Jochen Hoenicke for finding and reporting this
  issue. All users are advised to upgrade as soon as possible to minimise
  any potential impact.

- BIP38_KEY_TESTNET was changed to reflect the testnet network version. BIP38 testnet keys
  created with older versions of wally were not valid for testnet.

- API change of wally_tx_elements_input_init_alloc and wally_tx_add_elements_raw_input
  to also include the pegin witness.

## Version 0.6.4

- WALLY_SECP_RANDOMISE_LEN was renamed to WALLY_SECP_RANDOMIZE_LEN for
  consistency - You should change any references in your source when upgrading.

- A potential crash when parsing short base58check strings was fixed. Users
  are encouraged to upgrade to 0.6.4 if they parse untrusted/unvalidated
  base58check input into short (less than 5 byte) output buffers.

## Version 0.6.3

- No API changes

## Version 0.6.2

- Not released

## Version 0.6.1

- No API changes
