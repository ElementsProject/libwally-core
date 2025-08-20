# Changes

## Version 1.5.1

### Added
- python: Add wheels for Python 3.13, remove support for Python 3.8.

### Fixed
- python: Fix source builds for newer pip versions.
- java: Fix tx_get_input_signature_hash to allow passing a null cache to disable caching.

## Version 1.5.0

### Added
- psbt: Add psbt_get_input_signature_type to get the type of signature required by an input.
- descriptor: Add support for Elements el-prefixed descriptor builtins as used in rust-elements.
- descriptor: Add support for parsing Elements ct descriptors with slip77(), elip150() and raw hex blinding keys.
- descriptor: Add support for generating Elements confidential addresses from ct descriptors.
- descriptor: Expose functions to perform ELIP-150 blinding key tweaking.
- crypto: Add ec_public_key_tweak to tweak standard (non-xonly) pubkeys.
- elements: Add asset_blinding_key_to_ec_public_key to compute the blinding pubkey from a blinding key.

### Changed
- psbt: Speed up p2tr signing slightly.
- descriptor: Allow U type children for thresh() expressions.
- build: Further extend CI coverage for scan-build/valgrind/asan checks.

### Fixed
- tx: Fix taproot cached hashing when using external sha256 implementations.
- wasm: Fixes for es6 and cjs.
- address_to_scriptpubkey: Correctly handle WALLY_NETWORK_BITCOIN_REGTEST.
- amalgamation: Support all supported standard configurations. Minor improvements to make usage easier/more robust.
- Various minor code and build fixes.

## Version 1.4.0

### Added

- tx: Add caching to signature hash generation/PSBT signing making signing faster.
- tx: Add support for generating Elements taproot signature hashes and signing Elements taproot inputs.
- descriptor: Add support for "tr()/rawtr()" keyspend-only taproot descriptors.
- descriptor: Add support for parsing Elements-core compatible descriptors, including taproot.
- psbt: Add accessors for keypath/taproot related fields.
- pset: Add support for ELIP-101 genesis hash.
- psbt: Add support for serializing/parsing/combining signature-only PSBTs.
- script: Add support for generating Elements p2tr scripts.
- BIP85: Add support for deriving RSA keys via BIP85.
- base64/psbt: Add support for parsing from known length (non-NUL terminated) strings.
- build: Add Debian Bookworm docker build image.

### Changed

- tx: Re-implement signature hash generation to use less stack space and CPU independently of caching.
- amalgamation: Provide the amalgamated build as a single source file, make it simpler to use.
- build: CI improvements: New valgrind, scan-build and ubsan/addrcheck/etc builds. Add CI/test runs
  for builds with elements support disabled.
- build: Update/extend tests to make it easier to catch errors in the new CI builds.

### Fixed

- psbt: Fix detection of expired CSV inputs for v0 PSBTs.
- psbt: Fix finalization of non-optimized CSV inputs (e.g. Green Liquid 2of2).
- tx: Fix incorrect sighash masking for BTC taproot inputs.
- build: Various fixes and test improvements for non-Elements builds.
- Various minor code and build fixes.

## Version 1.3.1

### Added

- Elements: Add `wally_tx_get_elements_weight_discount` for computing ELIP-0200 weight discounts.

### Changed

- Update JS dependencies.

### Fixed

- Minor build/CI fixes.

## Version 1.3.0

### Added

- script: Add support for fetching the CSV block count for Green CSV scripts.
- psbt_finalize: Add support for finalizing Green CSV inputs.

### Changed

- PSBT: Do not serialize witness data for input non-witness UTXOs, in
  order to match the current behaviour of Bitcoin core.

### Fixed
- psbt_sign_bip32: Fix signing with parent/master keys. Only already-derived
  keys would result in signed inputs previously.
- PSET: Allow signing pre-segwit inputs.
- PSET: Allow generating explicit proofs for inputs with only a non-witness UTXO.
- wally_scriptpubkey_get_type: Mark all scripts starting with OP_RETURN as
  WALLY_SCRIPT_TYPE_OP_RETURN.

## Version 1.2.0

### Added

- Python: Add Python 3.12 wheels to the binary releases/PyPI.
- tx: expose `wally_tx_input_clone`/`wally_tx_input_clone` for input cloning.
- Build: Add new static analysis CI runs.

### Changed

- Javascript: The npm build now uses nodejs 20, as nodejs 16 is end-of-life.
- Android: Update android NDK to version 26b.
- libsecp256k1-zkp: The library has been updated to include the latest
  changes to its cmake infrastructure.
- cmake: Now takes advantage of the new libsecp256k1-zkp cmake files to build
  experimental modules and export the project in cmake style. cmake now also
  builds test and collects coverage data.

### Fixed

- Build: Don't use `which` on Debian as it is now deprecated.
- Various bug fixes from static analysis.
- Various build and documentation fixes.


## Version 1.1.0

### Added

- PSBT: Allow extracting partially finalized transactions in `wally_psbt_extract`
  by passing a new `WALLY_PSBT_EXTRACT_OPT_FINAL` flag.
- tx: Allow getting the number of items in a transactions input witness via
  `wally_tx_input_get_witness_num_items`/`wally_tx_get_input_witness_num_items`.

### Changed

### Fixed

- tx: tx_input_get_witness now correctly returns 0 bytes written if passed a
  NULL input.


## Version 1.0.0

This release contains ABI changes; it is not ABI compatibile with prior versions.

### Added

- The library version number is now available as compile time constants
  (`WALLY_MAJOR_VER`, `WALLY_MINOR_VER`, `WALLY_PATCH_VER`, `WALLY_BUILD_VER`),
  and at runtime via `wally_get_build_version`.
- Added support for wallet policies (https://github.com/bitcoin/bips/pull/1389).
- Added support for iterating and querying keys in descriptor/policy
  expressions, including support for key origin information such as
  fingerprint and path.
- The library allocation functions (which may be overridden by the caller
  at runtime) are now exposed as wally_[malloc|calloc|free|strdup|strdump_n].
  Libraries using wally that wish to respect the callers allocation strategy
  can use these to avoid having to expose their own customizable allocator.
- Added support for encrypted request/response protocols using ephemeral keys
  via aes_cbc_with_ecdh_key().
- The PyPI wheel uploads now include an sdist source distribution, allowing
  install on otherwise-unsupported architectures.

### Changed

- The library now follows semantic versioning as per https://semver.org/.
- Elements support is now enabled by default, reflecting the common library
  usage. Please see the `configure --help` entries for `--disable-elements`
  and `--disable-elements-abi` for details.
- The ABI of the library is now consistent by default regardless of whether
  it is built with or without Elements support.
- The constant EC_SIGNATURE_DER_MAX_LOW_R_LEN has been changed from 71 to 70,
  to reflect that wally always produced low-R, low-S signatures when grinding.
- When configured to build as a static library, linking to libwallycore.a
  requires additionally linking to libsecp256k1.a.
- Wally can now be configured to build against a system-wide libsecp256k1 by
  passing `--with-system-secp256k1` to configure.
- The Python wheel can now be built with standard Python tooling such as `build`,
  and can be built from an uploaded source distribution.
- The Python wheel can now be built with dynamic linking to libwallycore and
  libsecp256k1-zkp/libsecp256k1.
- libsecp256k1-zkp has been updated to the lastest master version as at
  the time of release.
- Some functions in the c++ header wally.hpp have changed interface slightly.
  Note that this header is deprecated and will be replaced in an upcoming
  release with higher level wrappers in the same manner as Python and JS.
- The docker-based builds have been streamlined and simplified. NPM builds in
  particular are now much faster.

### Fixed

- Fixed a bug affecting signing PSBT taproot inputs.
- Fixed extern libsecp256k1-zkp linkage for windows static builds.
- Several build fixes/improvements and CI updates have been made.


## Version 0.9.1
- PSET: When adding an Elements transaction output to a PSET, the nonce
  commitment was incorrectly mapped to the PSET output blinding key field.
  It is now correctly mapped to the ECDH public key field.
- Transaction versions less than 2 are now upgraded to version 2 when
  converting a version 0 PSBT to version 2.
- Fetching nested structures (e.g. witness stacks) from PSBTs where no
  structure is present now returns NULL without returning an error.
- Python wheels are no longer released for deprecated versions 3.6/3.7.
- Python wheels are now available through pip for musl-based x86 platforms
  such as Apline Linux.

## Version 0.9.0
- ABI: wally_descriptor_to_script_get_maximum_length has changed its arguments
  to match wally_descriptor_to_script.
- ABI: The vars_in variable substitution map argument to wally_descriptor_parse
  now expects its key and value length to match the actual length to substitute
  rather than including an extra byte. Since the map stores byte arrays and not
  strings, this is more consistent with the existing map API.

## Version 0.8.9
- libsecp256k1-zkp: The internal libsecp256k1 library version has been updated
  to fix a potential timing leak when compiling with clang v14 or later.
  Although there are no known exploits at this time, users are encouraged to
  update as soon as possible.
- descriptor_get_num_variants: Now returns 1 instead of 0 if no variants are
  present. This allows iterating the variant from 0 to the number of variants
  returned in order to generate all scripts/addresses.
- scriptpubkey_csv_2of3_then_2_from_bytes has been removed from the API.
- psbt: psbt_finalize now takes an extra flags parameter. The Java and Python
  wrappers default this to zero for backwards compatibility.
- psbt: output_index, sequence, required_locktime and required_lockheight are
  now returned as uint32_t values. Wrapped languages are not affected.

## Version 0.8.8
- witness_multisig_from_bytes: The length for the internally generated
  scriptsig was not calculated correctly, and not checked after generation.
  In rare cases where all signatures encode to the maximum DER signature
  encoding, this may cause an invalid write/read of 1-2 bytes past an
  allocated buffer. The severity of this depends on the users malloc
  implementation, but all users are encouraged to upgrade to the latest
  version. Note that the Jade and Bitbox02 hardware wallets and the Green
  wallet apps are confirmed to *not* be affected by this issue.
- The old Javascript and cordova wrappers have been removed. Users should move
  to the new JS wrappers which are significantly more functional.
- `WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN` was increased to account for future
  segwit versions, in accordance with BIP 141. The previous value is available
  as `WALLY_SEGWIT_V0_ADDRESS_PUBKEY_MAX_LEN`.

## Version 0.8.7
- Javascript: Add a new WASM-based JS + typescript wrapper for Node and
  browsers. This now supports the entire wally API and builds to an npm module.
- Javascript: The old JS wrappers are now deprecated and will be removed
  in the next release. Please report any issues with the replacement wrapper.
- psbt_extract now takes an extra flags parameter. The Java and Python
  wrappers default this to zero for backwards compatibility.
- bip39_mnemonic_to_seed is no longer available for SWIG-wrapped languages.
  Callers should use bip39_mnemonic_to_seed512 instead.
- Python: Remove support for Python 2.x.
- Python: The Python wrappers are now automatically generated. Please ensure
  you thoroughly test your Python code after upgrading.
- Python: Some calls (e.g. bip39_mnemonic_to_seed512, aes, and aes_cbc) used
  to take output buffers to fill and return the number of bytes written. These
  calls now automatically create and fill thier buffer, returning it as the
  only return value. The number of bytes written can be determined by using
  len() on the returned output buffer.

## Version 0.8.6
- Support for PSET v0 (Elements) has been removed.
- PSBT: PSBT/PSET v2 support has been added. The ABI has changed slightly as a result.
  Users will need to recompile their applications and change function names and
  arguments in the cases listed below:
- PSBT_PROPRIETARY_TYPE has been renamed to WALLY_PSBT_PROPRIETARY_TYPE to respect
  wallys namespace.
- psbt_init_alloc has changed its definition and now has a new flags argument.
  Passing `WALLY_PSBT_INIT_PSET` to this function will create an Elements
  PSET instead of a PSBT (version must be passed as 2 in this case).
- psbt_from_base64 and psbt_from_bytes now take an extra flags parameter. The
  Java and Python wrappers default this to zero for backwards compatibility.
- psbt_add_input_at has been renamed to psbt_add_tx_input_at.
- psbt_add_output_at has been renamed to psbt_add_tx_output_at.
- wally_map initialization functions now take a verification function
  as an extra parameter.
- wally_map_add_keypath_item has been renamed to wally_map_keypath_add.
  This call must only be made on a keypath initialized map.
- The input and output variants wally_psbt_input_add_keypath_item and
  wally_psbt_output_add_keypath_item have also been renamed to
  wally_psbt_input_keypath_add and wally_psbt_output_keypath_add.
- New functions wally_map_keypath_bip32_init_alloc and
  wally_map_keypath_public_key_init_alloc for initializing BIP32 and public key
  keypath maps have been added.
- Note that PSET support for issuance and peg-in is incomplete at this time and
  may contain bugs. Users are strongly advised to test their code thoroughly
  if using these features.

## Version 0.8.2

- struct wally_operations has changed to hold the size of the struct
  and has an additional member to allow overriding the lib secp context
  used internally. Users must recompile their applications against this
  version as a result (re-linking or simply upgrading the shared library
  is insufficient).

## Version 0.8.1

- Build: Note that the secp256k1-zkp library is now a git submodule rather
  than being directly checked in to the source tree. Run
  `git submodule sync --recursive` then `git submodule update --init --recursive`
  from the source tree in order to clone the secp source and build the library.
  When you sync this change initially you may need to `rm -r src/secp256k1` then
  `git checkout src/secp256k1` to remove any old files and achieve a clean
  source tree.

## Version 0.8.0

- No API changes

## Version 0.7.9

- Python: 'None' passed as a binary buffer argument to wally calls which
  require the buffer to be non-NULL now consistently throws ValueError (Just
  as the library does for incorrectly sized or otherwise invalid inputs).
  Previously this might throw a TypeError depending on the function.

- wally_is_elements_build now takes a size_t output instead of uin64_t.

- elements_pegout_script_from_bytes, asset_pak_whitelistproof and
  psbt_to_bytes now follow the library convention for too-short buffers
  instead of returning WALLY_EINVAL. See the generated API documentation
  section "Variable Length Output Buffers" for details.

- FINGERPRINT_LEN was renamed to BIP32_KEY_FINGERPRINT_LEN for
  consistency - You should change any references in your source when upgrading.

- Almost all functions comprising the PSBT interface have changed name,
  arguments, semantics or all three. Users can consider the new interface
  final for non-Elements PSBTs, however the Elements PSBT (PSET) interface
  and implementation will be changed in the next release to match the
  Elements codebase.

## Version 0.7.8

- Python 2 wheels are now deprecated. Users should move to Python 3 as soon as possible.

## Version 0.7.7

- API change of wally_asset_pak_whitelistproof to return the number of bytes written.

## Version 0.7.6

- No API changes

## Version 0.7.5

- No API changes

## Version 0.7.4

- No API changes

## Version 0.7.3

- No API changes

## Version 0.7.2

- API change of wally_tx_to_bytes and wally_tx_to_hex to not accept
  WALLY_TX_FLAG_USE_ELEMENTS set in flags. You should remove this flag when
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
