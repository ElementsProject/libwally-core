#ifndef LIBWALLY_CORE_SCRIPT_H
#define LIBWALLY_CORE_SCRIPT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Script opcodes */
#define OP_0 0x00
#define OP_FALSE 0x00
#define OP_PUSHDATA1 0x4c
#define OP_PUSHDATA2 0x4d
#define OP_PUSHDATA4 0x4e
#define OP_1NEGATE 0x4f
#define OP_RESERVED 0x50
#define OP_1 0x51
#define OP_TRUE 0x51
#define OP_2 0x52
#define OP_3 0x53
#define OP_4 0x54
#define OP_5 0x55
#define OP_6 0x56
#define OP_7 0x57
#define OP_8 0x58
#define OP_9 0x59
#define OP_10 0x5a
#define OP_11 0x5b
#define OP_12 0x5c
#define OP_13 0x5d
#define OP_14 0x5e
#define OP_15 0x5f
#define OP_16 0x60

#define OP_NOP 0x61
#define OP_VER 0x62
#define OP_IF 0x63
#define OP_NOTIF 0x64
#define OP_VERIF 0x65
#define OP_VERNOTIF 0x66
#define OP_ELSE 0x67
#define OP_ENDIF 0x68
#define OP_VERIFY 0x69
#define OP_RETURN 0x6a

#define OP_TOALTSTACK 0x6b
#define OP_FROMALTSTACK 0x6c
#define OP_2DROP 0x6d
#define OP_2DUP 0x6e
#define OP_3DUP 0x6f
#define OP_2OVER 0x70
#define OP_2ROT 0x71
#define OP_2SWAP 0x72
#define OP_IFDUP 0x73
#define OP_DEPTH 0x74
#define OP_DROP 0x75
#define OP_DUP 0x76
#define OP_NIP 0x77
#define OP_OVER 0x78
#define OP_PICK 0x79
#define OP_ROLL 0x7a
#define OP_ROT 0x7b
#define OP_SWAP 0x7c
#define OP_TUCK 0x7d

#define OP_CAT 0x7e
#define OP_SUBSTR 0x7f
#define OP_LEFT 0x80
#define OP_RIGHT 0x81
#define OP_SIZE 0x82

#define OP_INVERT 0x83
#define OP_AND 0x84
#define OP_OR 0x85
#define OP_XOR 0x86
#define OP_EQUAL 0x87
#define OP_EQUALVERIFY 0x88
#define OP_RESERVED1 0x89
#define OP_RESERVED2 0x8a

#define OP_1ADD 0x8b
#define OP_1SUB 0x8c
#define OP_2MUL 0x8d
#define OP_2DIV 0x8e
#define OP_NEGATE 0x8f
#define OP_ABS 0x90
#define OP_NOT 0x91
#define OP_0NOTEQUAL 0x92

#define OP_ADD 0x93
#define OP_SUB 0x94
#define OP_MUL 0x95
#define OP_DIV 0x96
#define OP_MOD 0x97
#define OP_LSHIFT 0x98
#define OP_RSHIFT 0x99

#define OP_BOOLAND 0x9a
#define OP_BOOLOR 0x9b
#define OP_NUMEQUAL 0x9c
#define OP_NUMEQUALVERIFY 0x9d
#define OP_NUMNOTEQUAL 0x9e
#define OP_LESSTHAN 0x9f
#define OP_GREATERTHAN 0xa0
#define OP_LESSTHANOREQUAL 0xa1
#define OP_GREATERTHANOREQUAL 0xa2
#define OP_MIN 0xa3
#define OP_MAX 0xa4

#define OP_WITHIN 0xa5

#define OP_RIPEMD160 0xa6
#define OP_SHA1 0xa7
#define OP_SHA256 0xa8
#define OP_HASH160 0xa9
#define OP_HASH256 0xaa
#define OP_CODESEPARATOR 0xab
#define OP_CHECKSIG 0xac
#define OP_CHECKSIGVERIFY 0xad
#define OP_CHECKMULTISIG 0xae
#define OP_CHECKMULTISIGVERIFY 0xaf

#define OP_NOP1 0xb0
#define OP_CHECKLOCKTIMEVERIFY 0xb1
#define OP_NOP2 0xb1
#define OP_CHECKSEQUENCEVERIFY 0xb2
#define OP_NOP3 0xb2
#define OP_NOP4 0xb3
#define OP_NOP5 0xb4
#define OP_NOP6 0xb5
#define OP_NOP7 0xb6
#define OP_NOP8 0xb7
#define OP_NOP9 0xb8
#define OP_NOP10 0xb9

#define OP_SMALLINTEGER 0xfa
#define OP_PUBKEYS 0xfb
#define OP_PUBKEYHASH 0xfd
#define OP_PUBKEY 0xfe

#define OP_INVALIDOPCODE 0xff

/**
 * Create a bitcoin script that pushes data to the stack.
 *
 * @bytes_in: Bytes to create a push script for.
 * @len_in: Length of @bytes_in in bytes.
 * @bytes_out: Destination for the resulting push script.
 * @len Size of @bytes_out in bytes.
 * @written: Destination for the number of bytes written to @bytes_out.
 */
WALLY_CORE_API int wally_push_from_bytes(
    const unsigned char *bytes_in,
    size_t len_in,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);


#define WALLY_SCRIPT_HASH160 0x1 /** hash160 input bytes before using them */
#define WALLY_SCRIPT_SHA256  0x2 /** sha256 input bytes before using them */
/* FIXME: Add a WALLY_SCRIPT_INITIAL_PUSH to make witness scriptSigs */

/**
 * Create a segwit witness program from a script or hash.
 *
 * @bytes_in: Script or hash bytes to create a witness program from.
 * @len_in: Length of @bytes_in in bytes. Must be @HASH160_LEN or @SHA256_LEN
 *      if neither @WALLY_SCRIPT_HASH160 or @WALLY_SCRIPT_SHA256 is given.
 * @flags: @WALLY_SCRIPT_HASH160 or @WALLY_SCRIPT_SHA256 to hash the input
 *     script before using it.
 * @bytes_out: Destination for the resulting witness program.
 * @len Size of @bytes_out in bytes.
 * @written: Destination for the number of bytes written to @bytes_out.
 */
WALLY_CORE_API int wally_witness_program_from_bytes(
    const unsigned char *bytes_in,
    size_t len_in,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_SCRIPT_H */

