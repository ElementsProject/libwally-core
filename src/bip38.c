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
    /* We passed salt in to the caller, so we know we can cast away const,
     * and that is has slack PBKDF2_SALT_BYTES in it.  */
    pbkdf2_hmac_sha256(pass, pass_len, (unsigned char *)salt, salt_len,
                       cost, bytes_out, len);
}

/* FIXME:
 * #ifdef HAVE_POSIX_MEMALIGN
 * #if !defined(MAP_ANON) || !defined(HAVE_MMAP)
 */
#include "scrypt/crypto_scrypt_smix.c"
#include "scrypt/crypto_scrypt.c"

/*
 * Our scrypt wrapper.
 */
int scrypt(const unsigned char *pass, size_t pass_len,
           const unsigned char *salt, size_t salt_len,
           uint64_t N, uint32_t r, uint32_t p,
           unsigned char *bytes_out, size_t len)
{
    /* Create a temp salt with space for slack bytes */
    unsigned char *tmp_salt = malloc(salt_len + PBKDF2_SALT_BYTES);
    int ret = -1;

    if (tmp_salt) {
        memcpy(tmp_salt, salt, salt_len);

        ret = _crypto_scrypt(pass, pass_len,
                             tmp_salt, salt_len + PBKDF2_SALT_BYTES,
                             N, r, p,
                             bytes_out, len,
                             crypto_scrypt_smix);
        free(tmp_salt);
    }
    return ret;
}
