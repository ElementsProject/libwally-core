#include <include/wally_bip38.h>
#include "internal.h"
#include "hmac.h"
#include "pbkdf2.h"
#include "ccan/ccan/endian/endian.h"
#include <string.h>

/* Implement functions required by the scrypt core */
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

static void PBKDF2_SHA256(const unsigned char *pass, size_t pass_len,
                          const unsigned char *salt, size_t salt_len,
                          uint64_t cost,
                          unsigned char *bytes_out, size_t len)
{
    /* We passed salt in to the caller, so we know we can cast away cons */
    pbkdf2_hmac_sha256(pass, pass_len, (unsigned char *)salt, salt_len,
                       cost, bytes_out, len);
}

/* FIXME:
 * #ifdef HAVE_POSIX_MEMALIGN
 * #if !defined(MAP_ANON) || !defined(HAVE_MMAP)
 */
#include "scrypt/crypto_scrypt_smix.c"
#define smix_func crypto_scrypt_smix
#include "scrypt/crypto_scrypt.c"
