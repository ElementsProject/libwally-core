#include <include/wally_bip38.h>
#include "internal.h"
#include "hmac.h"
#include "pbkdf2.h"
#include "ccan/ccan/endian/endian.h"
#include <string.h>

static uint32_t le32dec(const void *p)
{
    leint32_t tmp;
    memcpy(&tmp, p, sizeof(tmp));
    return le32_to_cpu(tmp);
}

static void le32enc(void *p, uint32_t value)
{
    leint32_t tmp = cpu_to_le32(value);
    memcpy(p, &tmp, sizeof(tmp));
}

static void PBKDF2_SHA256(const uint8_t *pass, size_t pass_len,
                          const uint8_t *salt, size_t salt_len,
                          uint64_t c, uint8_t *bytes_out, size_t dk_len)
{
    /* FIXME: Generalise our pbkdf2_hmac_sha512 and implement a 256 version,
     *        This is hacked to get it to compile.
     */
    size_t len = dk_len / PBKDF2_HMAC_SHA256_LEN;
    (void)c;
    pbkdf2_hmac_sha512(pass, pass_len, (void *)salt, salt_len, bytes_out, len);
}

/* FIXME:
 * #ifdef HAVE_POSIX_MEMALIGN
 * #if !defined(MAP_ANON) || !defined(HAVE_MMAP)
 */
#include "src/scrypt/crypto_scrypt_smix.c"
#define smix_func crypto_scrypt_smix
#include "src/scrypt/crypto_scrypt.c"
