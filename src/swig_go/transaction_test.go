package wallycore

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

var tx string = "0200000000012e4c6db69a4b99dee5a17a430fb57f84d45a6bb36abd0d1008bae22727a5c9e00000000000ffffffff0201f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000025408d6c0001976a9147f06a3ce008dbee41566aeb7cad70472e097cd9888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000000030d40000000000000"
var index int64 = 0
var privKeyHex string = ""
var value uint64 = 0
var script string = "76a914275f1c4afe86b62e0c8b4dfa7ee4dc74367206b488ac"

func TestTxGetElementsSignatureHash(t *testing.T) {
	sighash := uint32(WALLY_SIGHASH_ALL)
	txFlags := uint32(WALLY_TX_FLAG_USE_WITNESS + WALLY_TX_FLAG_USE_ELEMENTS)
	signatureHashFlags := uint32(0)
	expected := [32]uint8{
		0x16, 0x52, 0x1e, 0x28, 0xb3, 0x9, 0x26, 0xc3,
		0x3b, 0x7d, 0xc6, 0xb8, 0xbb, 0x4, 0x35, 0x96,
		0x4c, 0x8, 0xb7, 0xa8, 0x9f, 0x53, 0x4d, 0x36,
		0x22, 0xf2, 0x1b, 0x99, 0x4a, 0xf9, 0xa2, 0x78}
	scriptByte, _ := hex.DecodeString(script)
	wallyTx, _ := WallyTxFromHex(tx, txFlags)

	signatureHash, ret := WallyTxGetElementsSignatureHash(
		wallyTx,
		index,
		scriptByte,
		nil,
		sighash,
		signatureHashFlags)
	assert.Equal(t, 0, ret)
	assert.Equal(t, expected, signatureHash)
	WallyTxFree(wallyTx)
}

func TestTxGetVsize(t *testing.T) {
	txFlags := uint32(WALLY_TX_FLAG_USE_WITNESS + WALLY_TX_FLAG_USE_ELEMENTS)
	wallyTx, ret := WallyTxFromHex(tx, txFlags)
	assert.Equal(t, 0, ret)

	vsize, ret := WallyTxGetVsize(wallyTx)
	assert.Equal(t, 0, ret)
	assert.Equal(t, int64(165), vsize)
	WallyTxFree(wallyTx)
}
