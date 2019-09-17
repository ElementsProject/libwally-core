package wallycore

import (
	"testing"
	"github.com/stretchr/testify/assert"
//	"encoding/hex"
//	"fmt"
)

func TestHash160(t *testing.T) {
	pubkeyBytes := []byte{
		3, 57, 163, 96, 19, 48, 21, 151,
		218, 239, 65, 251, 229, 147, 160, 44,
		197, 19, 208, 181, 85, 39, 236, 45,
		241, 5, 14, 46, 143, 244, 156, 133, 
		194}
	expected := [20]uint8{
		0x34, 0x42, 0x19, 0x3e, 0x1b, 0xb7, 0x9, 0x16, 0xe9, 0x14,
		0x55, 0x21, 0x72, 0xcd, 0x4e, 0x2d, 0xbc, 0x9d, 0xf8, 0x11}
	pubkeyHash160, _ := WallyHash160(pubkeyBytes)
	assert.Equal(t, expected, pubkeyHash160)
}