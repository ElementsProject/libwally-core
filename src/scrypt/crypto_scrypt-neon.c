/*-
 * Copyright 2009 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */
#ifdef __ARM_NEON__

#include "scrypt_platform.h"
#include <arm_neon.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#ifdef USE_OPENSSL_PBKDF2
#include <openssl/evp.h>
#else
#include "sha256.h"
#endif
#include "sysendian.h"
#include "crypto_scrypt.h"
#include "crypto_scrypt-neon-salsa208.h"
static void blkcpy(void *, void *, size_t);
static void blkxor(void *, void *, size_t);
void crypto_core_salsa208_armneon2(void *);
static void blockmix_salsa8(uint8x16_t *, uint8x16_t *, uint8x16_t *, size_t);
static uint64_t integerify(void *, size_t);
static void smix(uint8_t *, size_t, uint64_t, void *, void *);
static void
blkcpy(void * dest, void * src, size_t len)
{
    uint8x16_t * D = dest;
    uint8x16_t * S = src;
    size_t L = len / 16;
    size_t i;
    for (i = 0; i < L; i++)
        D[i] = S[i];
}
static void
blkxor(void * dest, void * src, size_t len)
{
    uint8x16_t * D = dest;
    uint8x16_t * S = src;
    size_t L = len / 16;
    size_t i;
    for (i = 0; i < L; i++)
        D[i] = veorq_u8(D[i], S[i]);
}
/**
 * blockmix_salsa8(B, Y, r):
 * Compute B = BlockMix_{salsa20/8, r}(B).  The input B must be 128r bytes in
 * length; the temporary space Y must also be the same size.
 */
static void
blockmix_salsa8(uint8x16_t * Bin, uint8x16_t * Bout, uint8x16_t * X, size_t r)
{
    size_t i;
    /* 1: X <-- B_{2r - 1} */
    blkcpy(X, &Bin[8 * r - 4], 64);
    /* 2: for i = 0 to 2r - 1 do */
    for (i = 0; i < r; i++) {
        /* 3: X <-- H(X \xor B_i) */
        blkxor(X, &Bin[i * 8], 64);
        salsa20_8_intrinsic((void *) X);
        /* 4: Y_i <-- X */
        /* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
        blkcpy(&Bout[i * 4], X, 64);
        /* 3: X <-- H(X \xor B_i) */
        blkxor(X, &Bin[i * 8 + 4], 64);
        salsa20_8_intrinsic((void *) X);
        /* 4: Y_i <-- X */
        /* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
        blkcpy(&Bout[(r + i) * 4], X, 64);
    }
}
/**
 * integerify(B, r):
 * Return the result of parsing B_{2r-1} as a little-endian integer.
 */
static uint64_t
integerify(void * B, size_t r)
{
    uint8_t * X = (void*)((uintptr_t)(B) + (2 * r - 1) * 64);
    return (le64dec(X));
}
/**
 * smix(B, r, N, V, XY):
 * Compute B = SMix_r(B, N).  The input B must be 128r bytes in length; the
 * temporary storage V must be 128rN bytes in length; the temporary storage
 * XY must be 256r bytes in length.  The value N must be a power of 2.
 */
static void
smix(uint8_t * B, size_t r, uint64_t N, void * V, void * XY)
{
    uint8x16_t * X = XY;
    uint8x16_t * Y = (void *)((uintptr_t)(XY) + 128 * r);
    uint8x16_t * Z = (void *)((uintptr_t)(XY) + 256 * r);
    uint32_t * X32 = (void *)X;
    uint64_t i, j;
    size_t k;
    /* 1: X <-- B */
    blkcpy(X, B, 128 * r);
    /* 2: for i = 0 to N - 1 do */
    for (i = 0; i < N; i += 2) {
        /* 3: V_i <-- X */
        blkcpy((void *)((uintptr_t)(V) + i * 128 * r), X, 128 * r);
        /* 4: X <-- H(X) */
        blockmix_salsa8(X, Y, Z, r);
        /* 3: V_i <-- X */
        blkcpy((void *)((uintptr_t)(V) + (i + 1) * 128 * r),
               Y, 128 * r);
        /* 4: X <-- H(X) */
        blockmix_salsa8(Y, X, Z, r);
    }
    /* 6: for i = 0 to N - 1 do */
    for (i = 0; i < N; i += 2) {
        /* 7: j <-- Integerify(X) mod N */
        j = integerify(X, r) & (N - 1);
        /* 8: X <-- H(X \xor V_j) */
        blkxor(X, (void *)((uintptr_t)(V) + j * 128 * r), 128 * r);
        blockmix_salsa8(X, Y, Z, r);
        /* 7: j <-- Integerify(X) mod N */
        j = integerify(Y, r) & (N - 1);
        /* 8: X <-- H(X \xor V_j) */
        blkxor(Y, (void *)((uintptr_t)(V) + j * 128 * r), 128 * r);
        blockmix_salsa8(Y, X, Z, r);
    }
    /* 10: B' <-- X */
    blkcpy(B, X, 128 * r);
}

#endif // __ARM_NEON__
