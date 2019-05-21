%module wallycore
%{
#include <iostream>
#define BUILD_ELEMENTS 1
#include "include/wally_core.h"
#include "include/wally_crypto.h"
#include "include/wally_address.h"
#include "include/wally_bip32.h"
#include "include/wally_bip39.h"
#include "include/wally_transaction.h"
#include "include/wally_elements.h"
#include "include/wally_script.h"
%}

%typemap(argout) (char **output) {
    if ($1 && *$1) {
        $input->n = strlen(*$1);
    }
}
%rename("bip32_key_from_seed") bip32_key_from_seed_alloc;
%rename("bip32_key_unserialize") bip32_key_unserialize_alloc;
%rename("bip32_key_from_parent") bip32_key_from_parent_alloc;
%rename("bip32_key_from_parent_path") bip32_key_from_parent_path_alloc;
%rename("bip32_key_from_base58") bip32_key_from_base58_alloc;

%insert(cgo_comment_typedefs) %{
#cgo LDFLAGS: -L${SRCDIR}/src/.libs -lwallycore
%}
#include <iostream>
%include "../../include/wally_core.h"
%insert(go_wrapper) %{
/**
* Create a base 58 encoded string representing binary data.
*
* :param bytes: Binary data to convert.
* :param flags: Pass ``BASE58_FLAG_CHECKSUM`` if ``bytes`` should have a
*|    checksum calculated and appended before converting to base 58.
 */
func WallyBase58FromBytes(bytes []uint8, flags uint32) (base58 string, ret int) {
	tmpBytes := ([]byte)(bytes)
	wally_flags := SwigcptrUint32_t(uintptr(unsafe.Pointer(&flags)))
	ret = Wally_base58_from_bytes(&tmpBytes[0], int64(len(bytes)), wally_flags, &base58)
	return
}

/**
 * Decode a base 58 encoded string back into into binary data.
 *
 * :param str_in: Base 58 encoded string to decode.
 * :param flags: Pass ``BASE58_FLAG_CHECKSUM`` if ``bytes_out`` should have a
 *|    checksum validated and removed before returning. In this case, ``len``
 *|    must contain an extra ``BASE58_CHECKSUM_LEN`` bytes to calculate the
 *|    checksum into. The returned length will not include the checksum.
 * :param len: The length of ``bytes_out`` in bytes.
 */
func WallyBase58ToBytes(base58 string, flags uint32, byteLength int) ([]byte, int) {
	wally_flags := SwigcptrUint32_t(uintptr(unsafe.Pointer(&flags)))
	bytes := make([]byte, byteLength)
	written := int64(0)
	ret := Wally_base58_to_bytes(base58, wally_flags, &bytes[0], int64(len(bytes)), &written)
	return bytes[:written], ret
}
%}
%include "../../include/wally_crypto.h"
%insert(go_wrapper) %{
/**
 * RIPEMD-160(SHA-256(m))
 *
 * :param bytes: The message to hash
 */
func WallyHash160(bytes []byte) (hash160 [HASH160_LEN]byte, ret int){
	ret = Wally_hash160(&bytes[0], int64(len(bytes)), &hash160[0], int64(HASH160_LEN))
	return
}

/**
 * Create a public key from a private key.
 *
 * :param priv_key: The private key to create a public key from.
 */
func WallyEcPublicKeyFromPrivateKey(privkey [EC_PRIVATE_KEY_LEN]byte) (pubkey [EC_PUBLIC_KEY_LEN]byte, ret int) {
	ret = Wally_ec_public_key_from_private_key(&privkey[0], int64(len(privkey)), &pubkey[0], int64(len(pubkey)))
	return
}

/**
 * Sign a message hash with a private key, producing a compact signature.
 *
 * :param priv_key: The private key to sign with.
 * :param bytes: The message hash to sign.
 * :param flags: EC_FLAG_ flag values indicating desired behavior.
 */
func WallyEcSigFromBytes(privkey [EC_PRIVATE_KEY_LEN]byte, message []byte, flags uint32) (signature [EC_SIGNATURE_LEN]byte, ret int) {
	wally_flags := SwigcptrUint32_t(uintptr(unsafe.Pointer(&flags)))
	ret = Wally_ec_sig_from_bytes(&privkey[0], int64(len(privkey)), &message[0], int64(len(message)), wally_flags, &signature[0], int64(len(signature)))
	return
}

/**
 * Convert a compact signature to DER encoding.
 *
 * :param sig: The compact signature to convert.
 */
func WallyEcSigToDer(signature []byte) (der [EC_SIGNATURE_DER_MAX_LEN]byte, ret int) {
	written := int64(0)
	ret = Wally_ec_sig_to_der(&signature[0], int64(len(signature)), &der[0], int64(len(der)), &written)
	return
}

/**
 * Convert a DER encoded signature to a compact signature.
 *
 * :param bytes: The DER encoded signature to convert.
 */
func WallyEcSigFromDer(sigDer []byte) (signature [EC_SIGNATURE_LEN]byte, ret int) {
	ret = Wally_ec_sig_from_der(&sigDer[0], int64(len(sigDer)), &signature[0], int64(len(signature)))
	return
}
%}

%include "../../include/wally_address.h"
%insert(go_wrapper) %{
/**
 * Convert a Wallet Import Format string to a private key.
 *
 * :param wif: Private key in Wallet Import Format.
 * :param prefix: Prefix byte to use, e.g. 0x80, 0xef.
 * :param flags: Pass ``WALLY_WIF_FLAG_COMPRESSED`` if the corresponding pubkey is compressed,
 *|    otherwise ``WALLY_WIF_FLAG_UNCOMPRESSED``.
 */
func WallyWifToBytes(wif string, prefix uint32, flags uint32) (privkey [EC_PRIVATE_KEY_LEN]byte, ret int) {
	wally_prefix := SwigcptrUint32_t(uintptr(unsafe.Pointer(&prefix)))
	wally_flags := SwigcptrUint32_t(uintptr(unsafe.Pointer(&flags)))
	ret = Wally_wif_to_bytes(wif, wally_prefix, wally_flags, &privkey[0], int64(len(privkey)))
	return
}

/**
 * Extract the address from a confidential address.
 *
 * :param address: The base58 encoded confidential address to extract the address from.
 * :param prefix: The confidential address prefix byte, e.g. WALLY_CA_PREFIX_LIQUID.
 */
func WallyConfidentialAddrToAddr(confidentialAddress string, prefix uint32) (address string, ret int) {
	wally_prefix := SwigcptrUint32_t(uintptr(unsafe.Pointer(&prefix)))
	ret = Wally_confidential_addr_to_addr(confidentialAddress, wally_prefix, &address)
	return
}

/**
 * Extract the blinding public key from a confidential address.
 *
 * :param address: The base58 encoded confidential address to extract the public key from.
 * :param prefix: The confidential address prefix byte, e.g. WALLY_CA_PREFIX_LIQUID.
 */
func WallyConfidentialAddrToECPublicKey(confidentialAddress string, prefix uint32) (pubKey [EC_PUBLIC_KEY_LEN]byte, ret int) {
	wally_prefix := SwigcptrUint32_t(uintptr(unsafe.Pointer(&prefix)))
	ret = Wally_confidential_addr_to_ec_public_key(confidentialAddress, wally_prefix, &pubKey[0], int64(len(pubKey)))
	return
}

/**
 * Create a confidential address from an address and blinding public key.
 *
 * :param address: The base58 encoded address to make confidential.
 * :param prefix: The confidential address prefix byte, e.g. WALLY_CA_PREFIX_LIQUID.
 * :param pub_key: The blinding public key to associate with ``address``.
 */
func WallyConfidentialAddrFromAddr(addrBase58 string, prefix uint32, blindPubKey []byte) (confidentialAddress string, ret int) {
	wally_prefix := SwigcptrUint32_t(uintptr(unsafe.Pointer(&prefix)))
	ret = Wally_confidential_addr_from_addr(addrBase58, wally_prefix, &blindPubKey[0], int64(len(blindPubKey)), &confidentialAddress)
	return
}
%}
%include "../../include/wally_bip32.h"
%insert(go_wrapper) %{
type CCharArray struct {
	P *byte
	Length int64
}

type ExtKey struct {
	ChainCode [32]byte
	Fingerprint [20]byte
	Depth uint8
	Pad [10]byte
	PrivKey [33]byte
	Index uint32
	Hash160 [20]byte
	Version uint32
	Pad2 [3]byte
	PubKey [33]byte
}
func (k ExtKey)Swigcptr() uintptr {
	return uintptr(unsafe.Pointer(&k))
}

/**
 * Create a new master extended key from entropy.
 *
 * This creates a new master key, i.e. the root of a new HD tree.
 * The entropy passed in may produce an invalid key. If this happens,
 * WALLY_ERROR will be returned and the caller should retry with
 * new entropy.
 *
 * :param seed: Entropy to use.
 * :param version: Either ``BIP32_VER_MAIN_PRIVATE`` or ``BIP32_VER_TEST_PRIVATE``,
 *|     indicating mainnet or testnet/regtest respectively.
 * :param flags: Either ``BIP32_FLAG_SKIP_HASH`` to skip hash160 calculation, or 0.
 */
func Bip32KeyFromSeed(seed []byte, version uint32, flags uint32) (extKey *ExtKey, ret int) {
	wally_version := SwigcptrUint32_t(uintptr(unsafe.Pointer(&version)))
	wally_flags := SwigcptrUint32_t(uintptr(unsafe.Pointer(&flags)))
	var tmp uintptr
	extKeyOut := SwigcptrExt_key(unsafe.Pointer(&tmp))
	ret = Bip32_key_from_seed(
		&seed[0],
		int64(len(seed)),
		wally_version,
		wally_flags,
		extKeyOut,
	)

	if ret == 0 {
		extKey = (*ExtKey)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(extKeyOut))))
	}
	return
}

/**
 * Serialize an extended key to memory using BIP32 format.
 *
 * :param extKey: The extended key to serialize.
 * :param flags: BIP32_FLAG_KEY_ Flags indicating which key to serialize. You can not
 *|        serialize a private extended key from a public extended key.
 */
func Bip32KeySerialize(extKey *ExtKey, flags uint32) (extKeyBytes [BIP32_SERIALIZED_LEN]byte) {
	wally_flags := SwigcptrUint32_t(uintptr(unsafe.Pointer(&flags)))
	extKeyOut := CCharArray{&extKeyBytes[0], int64(BIP32_SERIALIZED_LEN)}

	Bip32_key_serialize(extKey, wally_flags, extKeyOut.P, extKeyOut.Length)
	return
}

/**
 * Convert an extended key to base58.
 *
 * :param extKey: The extended key.
 * :param flags: BIP32_FLAG_KEY_ Flags indicating which key to serialize. You can not
 *|        serialize a private extended key from a public extended key.
 */
func Bip32KeyToBase58(extKey *ExtKey, flags uint32) (xKeyBase58 string){
	wally_flags := SwigcptrUint32_t(uintptr(unsafe.Pointer(&flags)))

	Bip32_key_to_base58(extKey, wally_flags, &xKeyBase58)
	return
}

/**
 * Convert a base58 encoded extended key to an extended key.
 *
 * :param xKeyBase58: The extended key in base58.
 */
func Bip32KeyFromBase58(xKeyBase58 string) (extKey *ExtKey, ret int){
	var tmp uintptr
	extKeyOut := SwigcptrExt_key(unsafe.Pointer(&tmp))
	ret = Bip32_key_from_base58(xKeyBase58, extKeyOut)
	if ret == 0 {
		extKey = (*ExtKey)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(extKeyOut))))
	}
	return
}

/**
 * Create a new child extended key from a parent extended key.
 *
 * :param extKey: The parent extended key.
 * :param childNum: The child number to create. Numbers greater
 *|           than or equal to ``BIP32_INITIAL_HARDENED_CHILD`` represent
 *|           hardened keys that cannot be created from public parent
 *|           extended keys.
 * :param flags: BIP32_FLAG_KEY_ Flags indicating the type of derivation wanted.
 *|       You can not derive a private child extended key from a public
 *|       parent extended key.
 */
func Bip32KeyFromParent(extKey *ExtKey, childNum uint32, flags uint32) (childExtKey *ExtKey, ret int){
	wally_childNum := SwigcptrUint32_t(uintptr(unsafe.Pointer(&childNum)))
	wally_flags := SwigcptrUint32_t(uintptr(unsafe.Pointer(&flags)))
	var tmp uintptr
	extKeyOut := SwigcptrExt_key(unsafe.Pointer(&tmp))

	ret = Bip32_key_from_parent(extKey, wally_childNum, wally_flags, extKeyOut)
	if ret == 0 {
		childExtKey = (*ExtKey)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(extKeyOut))))
	}
	return
}

/**
 * Create a new child extended key from a parent extended key and a path.
 *
 * :param extKey: The parent extended key.
 * :param childPath: The path of child numbers to create.
 * :param flags: BIP32_KEY_ Flags indicating the type of derivation wanted.
 */
func Bip32KeyFromParentPath(extKey *ExtKey, childPath []uint8, flags uint32) (childExtKey *ExtKey, ret int){
	wally_child_path := SwigcptrUint32_t(uintptr(unsafe.Pointer(&childPath[0])))
	wally_flags := SwigcptrUint32_t(uintptr(unsafe.Pointer(&flags)))
	var tmp uintptr
	extKeyOut := SwigcptrExt_key(unsafe.Pointer(&tmp))
	ret = Bip32_key_from_parent_path(extKey, wally_child_path, int64(len(childPath)), wally_flags, extKeyOut)
	if ret == 0 {
		childExtKey = (*ExtKey)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(extKeyOut))))
	}
	return
}
%}

%include "../../include/wally_bip39.h"
%include "../../include/wally_transaction.h"
%insert(go_wrapper) %{
func charArrayToByteArray(script *uintptr, length uint64) (scriptBytes []byte) {
	if script == nil || length <= 0 {
		return
	}
	var b byte
	currentAddr := uintptr(unsafe.Pointer(script))
	for i := uint64(0); i < length; i++ {
		scriptBytes = append(scriptBytes, *(*byte)(unsafe.Pointer(currentAddr)))
		currentAddr = currentAddr + uintptr(unsafe.Sizeof(b))
	}
	return
}

type WallyTxWitnessItem struct {
	witness    *uintptr
	WitnessLen uint64
}

func (txwi WallyTxWitnessItem) WitnessToBytes() []byte {
	return charArrayToByteArray(txwi.witness, txwi.WitnessLen)
}

type WallyTxWitnessStack struct {
	items              *uintptr
	NumItems           uint64
	ItemsAllocationLen uint64
}

func (txws WallyTxWitnessStack) Swigcptr() uintptr {
	return uintptr(unsafe.Pointer(&txws))
}
func (txws WallyTxWitnessStack) ListItems() (items []*WallyTxWitnessItem) {
	structSize := unsafe.Sizeof(WallyTxWitnessItem{})
	items = make([]*WallyTxWitnessItem, txws.NumItems)
	if txws.NumItems < 1 {
		return
	}

	itemAddr := uintptr(unsafe.Pointer(txws.items))
	for i := uint64(0); i < txws.NumItems; i++ {
		items[i] = (*WallyTxWitnessItem)(unsafe.Pointer(itemAddr))
		itemAddr = itemAddr + structSize
	}
	return
}

type WallyTxInput struct {
	Txhash                      [WALLY_TXHASH_LEN]byte
	Index                       uint32
	Sequence                    uint32
	script                      *uintptr
	ScriptLen                   uint64
	witness                     *uintptr
	Features                    uint8
	BlindingNonce               [SHA256_LEN]byte
	Entropy                     [SHA256_LEN]byte
	issuanceAmount              *uintptr
	IssuanceAmountLen           uint64
	inflationKeys               *uintptr
	InflationKeysLen            uint64
	issuanceAmountRangeproof    *uintptr
	IssuanceAmountRangeproofLen uint64
	inflationKeysRangeproof     *uintptr
	InflationKeysRangeproofLen  uint64
	peginWitness                *uintptr
}

func (txi WallyTxInput) ScriptToBytes() []byte {
	return charArrayToByteArray(txi.script, txi.ScriptLen)
}
func (txi WallyTxInput) IssuanceAmountToBytes() []byte {
	return charArrayToByteArray(txi.issuanceAmount, txi.IssuanceAmountLen)
}
func (txi WallyTxInput) InflationKeysToBytes() []byte {
	return charArrayToByteArray(txi.inflationKeys, txi.InflationKeysLen)
}
func (txi WallyTxInput) IssuanceAmountRangeproofToBytes() []byte {
	return charArrayToByteArray(txi.issuanceAmountRangeproof, txi.IssuanceAmountRangeproofLen)
}
func (txi WallyTxInput) InflationKeysRangeproofToBytes() []byte {
	return charArrayToByteArray(txi.inflationKeysRangeproof, txi.InflationKeysRangeproofLen)
}
func (txi WallyTxInput) WitnessStack() (witnessStack *WallyTxWitnessStack) {
	if txi.witness != nil {
		witnessStack = (*WallyTxWitnessStack)(unsafe.Pointer(txi.witness))
	}
	return
}
func (txi WallyTxInput) PeginWitnessStack() (witnessStack *WallyTxWitnessStack) {
	if txi.peginWitness != nil {
		witnessStack = (*WallyTxWitnessStack)(unsafe.Pointer(txi.peginWitness))
	}
	return
}

type WallyTxOutput struct {
	Satoshi            uint64
	script             *uintptr
	ScriptLen          uint64
	Features           uint8
	asset              *uintptr
	AssetLen           uint64
	value              *uintptr
	ValueLen           uint64
	nonce              *uintptr
	NonceLen           uint64
	surjectionproof    *uintptr
	SurjectionproofLen uint64
	rangeproof         *uintptr
	RangeproofLen      uint64
}

func (txo WallyTxOutput) ScriptToBytes() []byte {
	return charArrayToByteArray(txo.script, txo.ScriptLen)
}
func (txo WallyTxOutput) AssetToBytes() []byte {
	return charArrayToByteArray(txo.asset, txo.AssetLen)
}
func (txo WallyTxOutput) ValueToBytes() []byte {
	return charArrayToByteArray(txo.value, txo.ValueLen)
}
func (txo WallyTxOutput) NonceToBytes() []byte {
	return charArrayToByteArray(txo.nonce, txo.NonceLen)
}
func (txo WallyTxOutput) SurjectionproofToBytes() []byte {
	return charArrayToByteArray(txo.surjectionproof, txo.SurjectionproofLen)
}
func (txo WallyTxOutput) RangeproofToBytes() []byte {
	return charArrayToByteArray(txo.rangeproof, txo.RangeproofLen)
}

type WallyTx struct {
	Version              uint32
	Locktime             uint32
	inputs               *uintptr
	NumInputs            uint64
	InputsAllocationLen  uint64
	outputs              *uintptr
	NumOutputs           uint64
	OutputsAllocationLen uint64
}

func (tx WallyTx) Swigcptr() uintptr {
	return uintptr(unsafe.Pointer(&tx))
}
func (tx WallyTx) ListInputs() (txInputs []*WallyTxInput) {
	structSize := unsafe.Sizeof(WallyTxInput{})
	txInputs = make([]*WallyTxInput, tx.NumInputs)
	if tx.NumInputs < 1 {
		return
	}

	inputAddr := uintptr(unsafe.Pointer(tx.inputs))
	for i := uint64(0); i < tx.NumInputs; i++ {
		txInputs[i] = (*WallyTxInput)(unsafe.Pointer(inputAddr))
		inputAddr = inputAddr + structSize
	}
	return
}
func (tx WallyTx) ListOutputs() (txOutputs []*WallyTxOutput) {
	structSize := unsafe.Sizeof(WallyTxOutput{})
	txOutputs = make([]*WallyTxOutput, tx.NumOutputs)
	if tx.NumOutputs < 1 {
		return
	}

	outputAddr := uintptr(unsafe.Pointer(tx.outputs))
	for i := uint64(0); i < tx.NumOutputs; i++ {
		txOutputs[i] = (*WallyTxOutput)(unsafe.Pointer(outputAddr))
		outputAddr = outputAddr + structSize
	}
	return
}

type WallyTxArgOutput uintptr

func (p WallyTxArgOutput) Swigcptr() uintptr {
	return (uintptr)(p)
}

func WallyTxFromHex(hex string, flags uint32) (wallyTx *WallyTx, ret int) {
	wallyTx = nil
	wally_flags := SwigcptrUint32_t(uintptr(unsafe.Pointer(&flags)))

	var tempWallyTx uintptr
	var p_wally_tx WallyTxArgOutput
	p_wally_tx = (WallyTxArgOutput)(unsafe.Pointer(&tempWallyTx))

	ret = Wally_tx_from_hex(hex, wally_flags, p_wally_tx)

	if ret == 0 {
		wallyTx = (*WallyTx)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(p_wally_tx))))
	}

	return
}

/**
 * Serialize a transaction to bytes.
 *
 * :param tx: The transaction to serialize.
 * :param flags: WALLY_TX_FLAG_ Flags controlling serialization options.
 * :param bytes_out: Destination for the serialized transaction.
 * :param len: Size of ``bytes_out`` in bytes.
 * :param written: Destination for the length of the serialized transaction.
 */
func WallyTxToBytes(wallyTx *WallyTx, flags uint32) (txbytes []byte, ret int) {
	wally_flags := SwigcptrUint32_t(uintptr(unsafe.Pointer(&flags)))
	txbytesBuf := make([]byte, 16048)
	written := int64(0)

	ret = Wally_tx_to_bytes(wallyTx, wally_flags, &txbytesBuf[0], int64(len(txbytesBuf)), &written)
	if ret == WALLY_OK {
		txbytes = txbytesBuf[:written]
	}
	return
}

/**
 * Set the scriptsig for an input in a transaction.
 *
 * :param tx: The transaction to operate on.
 * :param index: The zero-based index of the input to set the script on.
 * :param script: The scriptSig for the input.
 * :param script_len: Size of ``script`` in bytes.
 */
func WallyTxSetInputScript(wallyTx *WallyTx, index int64, script []byte) (ret int) {
	ret = Wally_tx_set_input_script(wallyTx, index, &script[0], int64(len(script)))
	return
}

/**
 * Add a transaction input to a transaction.
 *
 * :param tx: The transaction to add the input to.
 * :param txhash: The transaction hash of the transaction this input comes from.
 * :param index: The zero-based index of the transaction output in ``txhash`` that
 *|     this input comes from.
 * :param sequence: The sequence number for the input.
 * :param script: The scriptSig for the input.
 * :param witness: The witness stack for the input, or NULL if no witness is present.
 * :param flags: Flags controlling script creation. Must be 0.
 */
func WallyTxAddRawInput(
	wallyTx *WallyTx,
	txhash []byte,
	index uint32,
	seq uint32,
	script []byte,
	witness *WallyTxWitnessStack,
	flags uint32) (ret int) {

	wally_index := SwigcptrUint32_t(uintptr(unsafe.Pointer(&index)))
	wally_seq := SwigcptrUint32_t(uintptr(unsafe.Pointer(&seq)))
	wally_flags := SwigcptrUint32_t(uintptr(unsafe.Pointer(&flags)))

	ret = Wally_tx_add_raw_input(
		wallyTx,
		&txhash[0],
		int64(len(txhash)),
		wally_index,
		wally_seq,
		&script[0],
		int64(len(script)),
		witness,
		wally_flags)
	return
}

/**
 * Create a Elements transaction for signing and return its hash.
 *
 * :param tx: The transaction to generate the signature hash from.
 * :param index: The input index of the input being signed for.
 * :param script: The scriptSig for the input represented by ``index``.
 *|		if p2sh, set redeemscript
 * :param value: The (confidential) value spent by the input being signed for. Only used if
 *|     flags includes WALLY_TX_FLAG_USE_WITNESS, pass NULL otherwise.
 * :param sighash: WALLY_SIGHASH_ flags specifying the type of signature desired.
 * :param flags: WALLY_TX_FLAG_USE_WITNESS to generate a BIP 143 signature, or 0
 *|     to generate a pre-segwit Bitcoin signature.
 */
func WallyTxGetElementsSignatureHash(
	tx *WallyTx,
	index int64,
	scriptSig []byte,
	value []byte,
	sighash uint32,
	flags uint32) (signatureHash [SHA256_LEN]byte, ret int) {
	var wally_value *byte = nil
	valueLen := int64(0)
	if value != nil {
		wally_value = &value[0]
		valueLen = int64(len(value))
	}
	wally_sighash := SwigcptrUint32_t(uintptr(unsafe.Pointer(&sighash)))
	wally_flags := SwigcptrUint32_t(uintptr(unsafe.Pointer(&flags)))

	ret = Wally_tx_get_elements_signature_hash(
		tx,
		index,
		&scriptSig[0],
		int64(len(scriptSig)),
		wally_value,
		valueLen,
		wally_sighash,
		wally_flags,
		&signatureHash[0],
		int64(len(signatureHash)))
	return
}
%}

%include "../../include/wally_elements.h"
%insert(go_wrapper) %{
/**
 * asset is little endian byte order
 */
func WallyAssetUnblind(
	nonce []byte,
	blindPrivKey []byte, 
	proof []byte,
	valueCommitment []byte,
	extra []byte,
	assetCommitment []byte,
) (
	asset [32]byte,
	assetBlindFactor [32]byte,
	value uint64,
	valueBlindFactor [32]byte,
	ret int,
) {
	assetOut := CCharArray{&asset[0], int64(ASSET_TAG_LEN)}
	assetBlindFactorOut := CCharArray{&assetBlindFactor[0], int64(ASSET_TAG_LEN)}
	valueBlindFactorOut := CCharArray{&valueBlindFactor[0], int64(ASSET_TAG_LEN)}
	valueOut := SwigcptrUint64_t(unsafe.Pointer(&value))

	ret = Wally_asset_unblind(
		&nonce[0],
		int64(len(nonce)),
		&blindPrivKey[0],
		int64(len(blindPrivKey)),
		&proof[0],
		int64(len(proof)),
		&valueCommitment[0],
		int64(len(valueCommitment)),
		&extra[0],
		int64(len(extra)),
		&assetCommitment[0],
		int64(len(assetCommitment)),
		assetOut.P,
		assetOut.Length,
		assetBlindFactorOut.P,
		assetBlindFactorOut.Length,
		valueBlindFactorOut.P,
		valueBlindFactorOut.Length,
		valueOut,
	)
	return
}
%}

%include "../../include/wally_script.h"
%insert(go_wrapper) %{
/**
 * Determine the type of a scriptPubkey script.
 *
 * :param bytes: Bytes of the scriptPubkey.
 */
func WallyScriptpubkeyGetType(scriptPubKey []byte) (scriptType int64, ret int) {
	ret = Wally_scriptpubkey_get_type(&scriptPubKey[0], int64(len(scriptPubKey)), &scriptType)
	return
}

/**
 * Create a P2PKH scriptPubkey.
 *
 * :param pubKey: Bytes to create a scriptPubkey for.
 * :param flags: ``WALLY_SCRIPT_HASH160`` or 0.
 */
func WallyScriptpubkeyP2pkhFromBytes(pubKey []byte, flags uint32) (scriptBytes  [WALLY_SCRIPTPUBKEY_P2PKH_LEN]byte, ret int){
	wally_flags := SwigcptrUint32_t(uintptr(unsafe.Pointer(&flags)))
	written := int64(0)
	ret = Wally_scriptpubkey_p2pkh_from_bytes(
		&pubKey[0],
		int64(len(pubKey)),
		wally_flags,
		&scriptBytes[0],
		int64(len(scriptBytes)),
		&written)
	return
}

/**
 * Create a P2PKH scriptSig from a pubkey and compact signature.
 *
 * This function creates the scriptSig by converting ``sig`` to DER
 * encoding, appending the given sighash, then calling `wally_scriptsig_p2pkh_from_der`.
 *
 * :param pub_key: The public key to create a scriptSig with.
 * :param sig: The compact signature to create a scriptSig with.
 * :param sighash: WALLY_SIGHASH_ flags specifying the type of signature desired.
 */
func WallyScriptsigP2pkhFromSig(pubkey []byte, sig []byte, sighash uint32) (scriptSig []byte, ret int) {
	wally_sighash := SwigcptrUint32_t(uintptr(unsafe.Pointer(&sighash)))
	var scriptSigBuf [256]byte
	written := int64(0)
	ret = Wally_scriptsig_p2pkh_from_sig(&pubkey[0], int64(len(pubkey)), &sig[0], int64(len(sig)), wally_sighash, &scriptSigBuf[0], int64(len(scriptSigBuf)), &written)
	scriptSig = scriptSigBuf[:written]
	return
}

/**
 * Create a P2SH scriptPubkey.
 *
 * :param bytes: Bytes to create a scriptPubkey for.
 * :param flags: ``WALLY_SCRIPT_HASH160`` or 0.
 */
func WallyScriptpubkeyP2shFromBytes(redeemScript []byte, flags uint32) (scriptBytes [WALLY_SCRIPTPUBKEY_P2SH_LEN]byte, ret int){
	wally_flags := SwigcptrUint32_t(uintptr(unsafe.Pointer(&flags)))
	written := int64(0)
	ret = Wally_scriptpubkey_p2sh_from_bytes(
		&redeemScript[0],
		int64(len(redeemScript)),
		wally_flags,
		&scriptBytes[0],
		int64(len(scriptBytes)),
		&written)
	return
}

/**
 * Create a multisig scriptPubkey.
 *
 * :param bytes: Compressed public keys to create a scriptPubkey from.
 * :param threshold: The number of signatures that must match to satisfy the script.
 * :param flags: Must be zero.
 */
func WallyScriptpubkeyMultisigFromBytes(pubKeys []byte, threshold uint32, flags uint32) (redeemScript  []byte, ret int){
	wally_threshold := SwigcptrUint32_t(uintptr(unsafe.Pointer(&threshold)))
	wally_flags := SwigcptrUint32_t(uintptr(unsafe.Pointer(&flags)))
	pubkeyNum := len(pubKeys) / EC_PUBLIC_KEY_LEN
	scriptByteLen := int64(3 + (pubkeyNum * (EC_PUBLIC_KEY_LEN + 1)))
	redeemScript = make([]byte, scriptByteLen)
	written := int64(0)
	ret = Wally_scriptpubkey_multisig_from_bytes(
		&pubKeys[0],
		int64(len(pubKeys)),
		wally_threshold,
		wally_flags,
		&redeemScript[0],
		int64(len(redeemScript)),
		&written)
	return
}

/**
 * Create a multisig scriptSig.
 *
 * :param script: The redeem script this scriptSig provides signatures for.
 * :param bytes: Compact signatures to place in the scriptSig.
 * :param sighash: WALLY_SIGHASH_ flags for each signature in ``bytes``.
 * :param flags: Must be zero.
 */
func WallyScriptsigMultisigFromBytes(redeemScript []byte, signatures [][]byte, sighashes []uint32, flags uint32) (scriptSig []byte, ret int) {
	var signature []byte
	for i := 0; i < len(signatures); i++ {
		signature = append(signature, signatures[i]...)
	}
	wally_sighashes := SwigcptrUint32_t(uintptr(unsafe.Pointer(&sighashes[0])))
	wally_flags := SwigcptrUint32_t(uintptr(unsafe.Pointer(&flags)))
	var scriptSigBuf [256]byte
	written := int64(0)

	ret = Wally_scriptsig_multisig_from_bytes(
		&redeemScript[0],
		int64(len(redeemScript)),
		&signature[0],
		int64(len(signature)),
		wally_sighashes,
		int64(len(sighashes)),
		wally_flags,
		&scriptSigBuf[0],
		int64(len(scriptSigBuf)),
		&written)

	if ret == WALLY_OK {
		scriptSig = scriptSigBuf[:written]
	}
	return
}
%}
