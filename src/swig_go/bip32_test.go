package wallycore
/**
test vectors
@refer https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1
*/
import (
	"testing"
	"github.com/stretchr/testify/assert"
	"encoding/hex"
	"fmt"
)

func TestBip32KeyToBase58(t *testing.T) {
	seed := "000102030405060708090a0b0c0d0e0f"
	expectedXPriv := "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
	expectedXPub := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
	seedByte, _ := hex.DecodeString(seed)
	mXPrivKey, _ := Bip32KeyFromSeed(seedByte, uint32(BIP32_VER_MAIN_PRIVATE), 0)

	xprivbase58 := Bip32KeyToBase58(mXPrivKey, uint32(BIP32_FLAG_KEY_PRIVATE))
	assert.Equal(t, expectedXPriv, xprivbase58)
    xpubbase58 := Bip32KeyToBase58(mXPrivKey, uint32(BIP32_FLAG_KEY_PUBLIC))
	assert.Equal(t, expectedXPub, xpubbase58)
}

func TestBip32KeyFromBase58(t *testing.T) {
	xPrivBase58 := "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
	//xPubBase58 := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
	xPubBase58 := "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
	expectedPrivKeyHex := "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
	expectedPubKeyHex := "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
	xPriv, _ := Bip32KeyFromBase58(xPrivBase58)
	xPub, _ := Bip32KeyFromBase58(xPubBase58)
	fmt.Println(xPub)
	xPrivHex := hex.EncodeToString(xPriv.PrivKey[1:]) // strip the first byte
	xPubHex := hex.EncodeToString(xPub.PubKey[:])
	assert.Equal(t, expectedPrivKeyHex, xPrivHex)
	assert.Equal(t, expectedPubKeyHex, xPubHex)
}

func TestBip32KeyFromParent(t *testing.T) {
	seed := "000102030405060708090a0b0c0d0e0f"
	expectedXPrivKeyBase58 := "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
	seedByte, _ := hex.DecodeString(seed)
	mXPrivKey, _ := Bip32KeyFromSeed(seedByte, uint32(BIP32_VER_MAIN_PRIVATE), 0)
    xPriv_0h, _ := Bip32KeyFromParent(mXPrivKey, uint32(BIP32_INITIAL_HARDENED_CHILD), uint32(BIP32_FLAG_KEY_PRIVATE))
    xpriv_0h_base58 := Bip32KeyToBase58(xPriv_0h, uint32(BIP32_FLAG_KEY_PRIVATE))
	assert.Equal(t, expectedXPrivKeyBase58, xpriv_0h_base58)
}

func TestBip32KeyFromParentPath(t *testing.T) {
	seed := "000102030405060708090a0b0c0d0e0f"
	expectedPubKeyBase58 := "xpub6E7Cmt6yquwnWdDgsxJPcm9x5s2JREsirsGLqZ1E1Sap4iJTo4LsMPDmNDrEB56Eh1bKzzQyu83rgWgraCnKrLwGpGPZjSaMSkmauHSEJ1Z"
	seedByte, _ := hex.DecodeString(seed)
	mXPrivKey, _ := Bip32KeyFromSeed(seedByte, uint32(BIP32_VER_MAIN_PRIVATE), 0)
	path := []uint8{1,2,1,2} // M/1/2/1/2
    xPub, _ := Bip32KeyFromParentPath(mXPrivKey, path, uint32(BIP32_FLAG_KEY_PUBLIC))
    xPubBase58 := Bip32KeyToBase58(xPub, uint32(BIP32_FLAG_KEY_PUBLIC))
	assert.Equal(t, expectedPubKeyBase58, xPubBase58)
}