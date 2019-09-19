package wallycore

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"encoding/hex"
)
// version prefix
const (
	// [ liquid main net ]
	PREFIX_PUBKEY_ADDRESS_LIQUID = 57
	PREFIX_SCRIPT_ADDRESS_LIQUID = 39
	PREFIX_BLINDED_ADDRESS_LIQUID = 12
	PREFIX_SECRET_KEY_LIQUID = 128
	PREFIX_EXT_PUBLIC_KEY_LIQUID = 76067358 //(04 88 B2 1E)
	PREFIX_EXT_SECRET_KEY_LIQUID = 76066276 //(04 88 AD E4)

	// [ liquid regtest ]
	PREFIX_PUBKEY_ADDRESS_LIQUID_REGTEST = 235
	PREFIX_SCRIPT_ADDRESS_LIQUID_REGTEST = 75
	PREFIX_BLINDED_ADDRESS_LIQUID_REGTEST = 4
	PREFIX_SECRET_KEY_LIQUID_REGTEST = 239
	PREFIX_EXT_PUBLIC_KEY_LIQUID_REGTEST = 76067358 //(04 88 B2 1E)
	PREFIX_EXT_SECRET_KEY_LIQUID_REGTEST = 76066276 //(04 88 AD E4)
)

func TestCreateP2PKHAddress(t *testing.T) {
	pubKey := []byte{
		3, 57, 163, 96, 19, 48, 21, 151,
		218, 239, 65, 251, 229, 147, 160, 44,
		197, 19, 208, 181, 85, 39, 236, 45,
		241, 5, 14, 46, 143, 244, 156, 133, 
		194}
	expected := "2deC4i75MfFubhRsFUTuHuQB4v7cy7hXeb8"
	hash160, _ := WallyHash160(pubKey)
	bytes := []byte{byte(PREFIX_PUBKEY_ADDRESS_LIQUID_REGTEST)}
	bytes = append(bytes, hash160[:]...)
	P2PKHAddress, _ := WallyBase58FromBytes(bytes, uint32(BASE58_FLAG_CHECKSUM))
	assert.Equal(t, expected, P2PKHAddress)
}

func TestConfidentialAddrFromAddr(t *testing.T) {
	pubKey := []byte{
		3, 57, 163, 96, 19, 48, 21, 151,
		218, 239, 65, 251, 229, 147, 160, 44,
		197, 19, 208, 181, 85, 39, 236, 45,
		241, 5, 14, 46, 143, 244, 156, 133, 
		194}
	blindPubKey, _ := hex.DecodeString("032abd31b2a8cd405e72e2346266902bd97f1640c54408c007fc73c2517bdb1c8b")
	expected := "CTEsmtyKic5ZWFTwyesnLM4SV3KEF6HjtUGyieeM5EUzaaQMC9fuUKxEjGBmrHPNaxfuSLpUPe9ioP6r"
	hash160, _ := WallyHash160(pubKey)
	bytes := []byte{byte(PREFIX_PUBKEY_ADDRESS_LIQUID_REGTEST)}
	blindPubKeyCopy := [EC_PUBLIC_KEY_LEN]byte{byte(EC_PUBLIC_KEY_LEN)}
	copy(blindPubKeyCopy[:], blindPubKey)
	bytes = append(bytes, hash160[:]...)
	P2PKHAddress, _ := WallyBase58FromBytes(bytes, uint32(BASE58_FLAG_CHECKSUM))
	confidential, _ := WallyConfidentialAddrFromAddr(P2PKHAddress, uint32(PREFIX_BLINDED_ADDRESS_LIQUID_REGTEST), blindPubKeyCopy)
	assert.Equal(t, expected, confidential)
}

func TestConfidentialAddrToAddr(t *testing.T) {
	confidentialAddr := "CTEsmtyKic5ZWFTwyesnLM4SV3KEF6HjtUGyieeM5EUzaaQMC9fuUKxEjGBmrHPNaxfuSLpUPe9ioP6r"
	expected := "2deC4i75MfFubhRsFUTuHuQB4v7cy7hXeb8"
	addr, _ := WallyConfidentialAddrToAddr(confidentialAddr, uint32(PREFIX_BLINDED_ADDRESS_LIQUID_REGTEST))
	assert.Equal(t, expected, addr)
}

func TestConfidentialAddrToECPublicKey(t *testing.T) {
	confidentialAddr := "CTEsmtyKic5ZWFTwyesnLM4SV3KEF6HjtUGyieeM5EUzaaQMC9fuUKxEjGBmrHPNaxfuSLpUPe9ioP6r"
	expected, _ := hex.DecodeString("032abd31b2a8cd405e72e2346266902bd97f1640c54408c007fc73c2517bdb1c8b")
	blindPubKey, ret := WallyConfidentialAddrToECPublicKey(confidentialAddr, uint32(PREFIX_BLINDED_ADDRESS_LIQUID_REGTEST))
	assert.Equal(t, 0, ret)
	assert.Equal(t, expected, blindPubKey[:])
}