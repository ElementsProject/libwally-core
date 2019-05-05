package wallycore

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestScriptpubkeyP2pkhFromBytes(t *testing.T) {
	pubKey := []byte{
		3, 57, 163, 96, 19, 48, 21, 151,
		218, 239, 65, 251, 229, 147, 160, 44,
		197, 19, 208, 181, 85, 39, 236, 45,
		241, 5, 14, 46, 143, 244, 156, 133, 
		194}
	expected := [25]uint8{
		0x76, 0xa9, 0x14, 0x34, 0x42, 0x19, 0x3e, 0x1b, 0xb7, 0x9,
		0x16, 0xe9, 0x14, 0x55, 0x21, 0x72, 0xcd, 0x4e, 0x2d, 0xbc,
		0x9d, 0xf8, 0x11, 0x88, 0xac}
	script, _ := WallyScriptpubkeyP2pkhFromBytes(pubKey, uint32(WALLY_SCRIPT_HASH160))
	assert.Equal(t, expected, script)
}

func TestWallyScriptpubkeyMultisigFromBytes(t *testing.T) {
	pubKeyA := []byte{
		3, 57, 163, 96, 19, 48, 21, 151,
		218, 239, 65, 251, 229, 147, 160, 44,
		197, 19, 208, 181, 85, 39, 236, 45,
		241, 5, 14, 46, 143, 244, 156, 133, 
		194}
	pubKeyB := []byte{
		3, 90, 120, 70, 98, 164, 162, 10,
		101, 191, 106, 171, 154, 233, 138, 108,
		6, 138, 129, 197, 46, 75, 3, 44,
		15, 181, 64, 12, 112, 108, 252, 204,
		86}
	expected := []byte{
		0x52, 
		0x21, 
		0x3, 0x39, 0xa3, 0x60, 0x13, 0x30, 0x15, 0x97, 0xda, 0xef, 0x41, 0xfb, 0xe5, 0x93, 0xa0, 0x2c, 0xc5, 0x13, 0xd0, 0xb5, 0x55, 0x27, 0xec, 0x2d, 0xf1, 0x5, 0xe, 0x2e, 0x8f, 0xf4, 0x9c, 0x85, 0xc2,
		0x21,
		0x3, 0x5a, 0x78, 0x46, 0x62, 0xa4, 0xa2, 0xa, 0x65, 0xbf, 0x6a, 0xab, 0x9a, 0xe9, 0x8a, 0x6c, 0x6, 0x8a, 0x81, 0xc5, 0x2e, 0x4b, 0x3, 0x2c, 0xf, 0xb5, 0x40, 0xc, 0x70, 0x6c, 0xfc, 0xcc, 0x56, 0x52,
		0xae}
	pubKeys := append(pubKeyA, pubKeyB...)
	script, _ := WallyScriptpubkeyMultisigFromBytes(pubKeys, uint32(2), uint32(0))
	assert.Equal(t, expected, script)
}

func TestScriptpubkeyP2shFromBytes(t *testing.T) {
	pubKeyA := []byte{
		3, 57, 163, 96, 19, 48, 21, 151,
		218, 239, 65, 251, 229, 147, 160, 44,
		197, 19, 208, 181, 85, 39, 236, 45,
		241, 5, 14, 46, 143, 244, 156, 133, 
		194}
	pubKeyB := []byte{
		3, 90, 120, 70, 98, 164, 162, 10,
		101, 191, 106, 171, 154, 233, 138, 108,
		6, 138, 129, 197, 46, 75, 3, 44,
		15, 181, 64, 12, 112, 108, 252, 204,
		86}
	expected := [23]uint8{
		0xa9,
		0x14,
		0x5d, 0x5f, 0x5c, 0x3a, 0xd8, 0x12, 0xbf, 0x6e, 0xb5, 0xb3, 0x8, 0x58, 0xbe, 0xa4, 0xb3, 0xb2, 0x2f, 0xc0, 0x3b, 0x5,
		0x87}
	pubKeys := append(pubKeyA, pubKeyB...)
	redeemScript, _ := WallyScriptpubkeyMultisigFromBytes(pubKeys, uint32(2), uint32(0))
	script, _ := WallyScriptpubkeyP2shFromBytes(redeemScript, uint32(WALLY_SCRIPT_HASH160))
	assert.Equal(t, expected, script)
}