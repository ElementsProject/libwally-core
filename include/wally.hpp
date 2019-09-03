#ifndef LIBWALLY_CORE_WALLY_HPP
#define LIBWALLY_CORE_WALLY_HPP
#pragma once

#include <type_traits>
#include <string>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_bip38.h>
#include <wally_bip39.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_script.h>
#include <wally_transaction.h>

/* These wrappers allow passing containers such as std::vector, std::array,
 * std::string and custom classes as input/output buffers to wally functions.
 */
namespace wally {

namespace detail {
template <class P> inline auto get_p(const P& p, std::false_type, std::true_type) {
    return &p[0];
}
template <class P> inline auto get_p(const P& p, std::true_type, std::false_type) {
    return p;
}
template <class P> inline auto get_p(const P& p, std::false_type, std::false_type) {
    return p.get();
}
template <class P> inline auto get_p(const P& p) {
    return get_p(p, std::is_pointer<P>{}, std::is_array<P>{});
}
template <> inline auto get_p(const std::string& p) {
    return p.c_str();
}
template <> inline auto get_p(const std::nullptr_t& p) {
    return p;
}
} /* namespace detail */

#define WALLYP(var) detail::get_p(var) // Pointer, smart pointer or string
#define WALLYB(var) var.data(), var.size() // Input array/length
#define WALLYO(var) var.data(), var.size() // Output array/length

#define WALLY_FN_3(F, N) inline int F(uint32_t i321) { return ::N(i321); }

#define WALLY_FN_333_BBBBBA(F, N) template <class I1, class I2, class I3, class I4, class I5, class O> inline int F(uint32_t i321, uint32_t i322, uint32_t i323, const I1 &i1, const I2 &i2, const I3 &i3, const I4 &i4, const I5 &i5, O * *out) { \
        return ::N(i321, i322, i323, WALLYB(i1), WALLYB(i2), WALLYB(i3), WALLYB(i4), WALLYB(i5), out); \
}

#define WALLY_FN_33SS_A(F, N) template <class O> inline int F(uint32_t i321, uint32_t i322, size_t s1, size_t s2, O * *out) { \
        return ::N(i321, i322, s1, s2, out); \
}

#define WALLY_FN_3_A(F, N) template <class O> inline int F(uint32_t i321, O * *out) { \
        return ::N(i321, out); \
}

#define WALLY_FN_6_B(F, N) template <class O> inline int F(uint64_t i641, O & out) { \
        return ::N(i641, WALLYO(out)); \
}

#define WALLY_FN_6B_A(F, N) template <class I1, class O> inline int F(uint64_t i641, const I1 &i1, O * *out) { \
        return ::N(i641, WALLYB(i1), out); \
}

#define WALLY_FN_6BBBBBB_A(F, N) template <class I1, class I2, class I3, class I4, class I5, class I6, class O> \
    inline int F(uint64_t i641, const I1 &i1, const I2 &i2, const I3 &i3, const I4& i4, const I5 &i5, const I6 &i6, O * *out) { \
        return ::N(i641, WALLYB(i1), WALLYB(i2), WALLYB(i3), WALLYB(i4), WALLYB(i5), WALLYB(i6), out); \
}

#define WALLY_FN_B(F, N) template <class I> inline int F(const I &i1) { return ::N(WALLYB(i1)); }

#define WALLY_FN_B33BP_A(F, N) template <class I1, class I2, class P1, class O> inline int F(const I1 &i1, uint32_t i321, uint32_t i322, const I2 &i2, const P1 &p1, O * *out) { \
        return ::N(WALLYB(i1), i321, i322, WALLYB(i2), WALLYP(p1), out); \
}

#define WALLY_FN_B33_A(F, N) template <class I1, class O> inline int F(const I1 &i1, uint32_t i321, uint32_t i322, O * *out) { \
        return ::N(WALLYB(i1), i321, i322, out); \
}

#define WALLY_FN_B33_BS(F, N) template <class I1, class O> inline int F(const I1 &i1, uint32_t i321, uint32_t i322, O & out, size_t * written = 0) { \
        size_t n; \
        int ret = ::N(WALLYB(i1), i321, i322, WALLYO(out), written ? written : &n); \
        return written || ret != WALLY_OK ? ret : n == static_cast<size_t>(out.size()) ? WALLY_OK : WALLY_EINVAL; \
}

#define WALLY_FN_B33_P(F, N) template <class I1, class O> inline int F(const I1 &i1, uint32_t i321, uint32_t i322, O * out) { \
        return ::N(WALLYB(i1), i321, i322, out); \
}

#define WALLY_FN_B3_A(F, N) template <class I1, class O> inline int F(const I1 &i1, uint32_t i321, O * *out) { \
        return ::N(WALLYB(i1), i321, out); \
}

#define WALLY_FN_B3_BS(F, N) template <class I1, class O> inline int F(const I1 &i1, uint32_t i321, O & out, size_t * written = 0) { \
        size_t n; \
        int ret = ::N(WALLYB(i1), i321, WALLYO(out), written ? written : &n); \
        return written || ret != WALLY_OK ? ret : n == static_cast<size_t>(out.size()) ? WALLY_OK : WALLY_EINVAL; \
}

#define WALLY_FN_B3_B(F, N) template <class I1, class O> inline int F(const I1 &i1, uint32_t i321, O & out) { \
        return ::N(WALLYB(i1), i321, WALLYO(out)); \
}

#define WALLY_FN_B3B_B(F, N) template <class I1, class I2, class O> inline int F(const I1 &i1, uint32_t i321, const I2 &i2, O & out) { \
        return ::N(WALLYB(i1), i321, WALLYB(i2), WALLYO(out)); \
}

#define WALLY_FN_BB333_B(F, N) template <class I1, class I2, class O> inline int F(const I1 &i1, const I2 &i2, uint32_t i321, uint32_t i322, uint32_t i323, O & out) { \
        return ::N(WALLYB(i1), WALLYB(i2), i321, i322, i323, WALLYO(out)); \
}

#define WALLY_FN_BB3_A(F, N) template <class I1, class I2, class O> inline int F(const I1 &i1, const I2 &i2, uint32_t i321, O * *out) { \
        return ::N(WALLYB(i1), WALLYB(i2), i321, out); \
}

#define WALLY_FN_BB3_B(F, N) template <class I1, class I2, class O> inline int F(const I1 &i1, const I2 &i2, uint32_t i321, O & out) { \
        return ::N(WALLYB(i1), WALLYB(i2), i321, WALLYO(out)); \
}

#define WALLY_FN_BB3_BS(F, N) template <class I1, class I2, class O> inline int F(const I1 &i1, const I2 &i2, uint32_t i321, O & out, size_t * written = 0) { \
        size_t n; \
        int ret = ::N(WALLYB(i1), WALLYB(i2), i321, WALLYO(out), written ? written : &n); \
        return written || ret != WALLY_OK ? ret : n == static_cast<size_t>(out.size()) ? WALLY_OK : WALLY_EINVAL; \
}

#define WALLY_FN_BBB3_BS(F, N) template <class I1, class I2, class I3, class O> inline int F(const I1 &i1, const I2 &i2, const I3 &i3, uint32_t i321, O & out, size_t * written = 0) { \
        size_t n; \
        int ret = ::N(WALLYB(i1), WALLYB(i2), WALLYB(i3), i321, WALLYO(out), written ? written : &n); \
        return written || ret != WALLY_OK ? ret : n == static_cast<size_t>(out.size()) ? WALLY_OK : WALLY_EINVAL; \
}

#define WALLY_FN_BB_B(F, N) template <class I1, class I2, class O> inline int F(const I1 &i1, const I2 &i2, O & out) { \
        return ::N(WALLYB(i1), WALLYB(i2), WALLYO(out)); \
}

#define WALLY_FN_BP3_A(F, N) template <class I1, class P1, class O> inline int F(const I1 &i1, const P1 &p1, uint32_t i321, O * *out) { \
        return ::N(WALLYB(i1), WALLYP(p1), i321, out); \
}

#define WALLY_FN_BB_BS(F, N) template <class I1, class I2, class O> inline int F(const I1 &i1, const I2 &i2, O & out, size_t * written = 0) { \
        size_t n; \
        int ret = ::N(WALLYB(i1), WALLYB(i2), WALLYO(out), written ? written : &n); \
        return written || ret != WALLY_OK ? ret : n == static_cast<size_t>(out.size()) ? WALLY_OK : WALLY_EINVAL; \
}

#define WALLY_FN_B_A(F, N) template <class I1, class O> inline int F(const I1 &i1, O * *out) { \
        return ::N(WALLYB(i1), out); \
}

#define WALLY_FN_B_B(F, N) template <class I, class O> inline int F(const I &i1, O & out) { \
        return ::N(WALLYB(i1), WALLYO(out)); \
}

#define WALLY_FN_B_BS(F, N) template <class I, class O> inline int F(const I &i1, O & out, size_t * written = 0) { \
        size_t n; \
        int ret = ::N(WALLYB(i1), WALLYO(out), written ? written : &n); \
        return written || ret != WALLY_OK ? ret : n == static_cast<size_t>(out.size()) ? WALLY_OK : WALLY_EINVAL; \
}

#define WALLY_FN_B_P(F, N) template <class I1, class O> inline int F(const I1 &i1, O * out) { \
        return ::N(WALLYB(i1), out); \
}

#define WALLY_FN_B_S(F, N) template <class I> inline int F(const I &i1, size_t * written) { \
        return ::N(WALLYB(i1), written); \
}

#define WALLY_FN_BB33_B(F, N) template <class I1, class I2, class O> inline int F(const I1 &i1, const I2 &i2, uint32_t i321, uint32_t i322, O & out) { \
        return ::N(WALLYB(i1), WALLYB(i2), i321, i322, WALLYO(out)); \
}

#define WALLY_FN_P(F, N) template <class P1> inline int F(const P1 &p1) { \
        return ::N(WALLYP(p1)); \
}

#define WALLY_FN_P3(F, N) template <class P1> inline int F(const P1 &p1, uint32_t i321) { \
        return ::N(WALLYP(p1), i321); \
}

#define WALLY_FN_P33(F, N) template <class P1> inline int F(const P1 &p1, uint32_t i321, uint32_t i322) { \
        return ::N(WALLYP(p1), i321, i322); \
}

#define WALLY_FN_P33_P(F, N) template <class P1, class O> inline int F(const P1 &p1, uint32_t i321, uint32_t i322, O * out) { \
        return ::N(WALLYP(p1), i321, i322, out); \
}

#define WALLY_FN_P3B(F, N) template <class P1, class I1, class O> inline int F(const P1 &p1, uint32_t i321, const I1 &i1, O & out) { \
        return ::N(WALLYP(p1), i321, WALLYB(i1), WALLYO(out)); \
}

#define WALLY_FN_P3B633_B(F, N) template <class P1, class I1, class O> inline int F(const P1 &p1, uint32_t i321, const I1 &i1, uint64_t i641, uint32_t i322, uint32_t i323, O & out) { \
        return ::N(WALLYP(p1), i321, WALLYB(i1), i641, i322, i323, WALLYO(out)); \
}

#define WALLY_FN_P3BB36333_B(F, N) \
    template <class P1, class I1, class I2, class O> \
    inline int F(const P1 &p1, uint32_t i321, const I1 &i1, const I2 &i2,  uint32_t i322, uint64_t i641, uint32_t i323, uint32_t i324, uint32_t i325, O & out) { \
        return ::N(WALLYP(p1), i321, WALLYB(i1), WALLYB(i2), i322, i641, i323, i324, i325, WALLYO(out)); \
    }

#define WALLY_FN_P3_A(F, N) template <class P1, class O> inline int F(const P1 &p1, uint32_t i321, O * *out) { \
        return ::N(WALLYP(p1), i321, out); \
}

#define WALLY_FN_P3_B(F, N) template <class P1, class O> inline int F(const P1 &p1, uint32_t i321, O & out) { \
        return ::N(WALLYP(p1), i321, WALLYO(out)); \
}

#define WALLY_FN_P3_BS(F, N) template <class P1, class O> inline int F(const P1 &p1, uint32_t i321, O & out, size_t * written = 0) { \
        size_t n; \
        int ret = ::N(WALLYP(p1), i321, WALLYO(out), written ? written : &n); \
        return written || ret != WALLY_OK ? ret : n == static_cast<size_t>(out.size()) ? WALLY_OK : WALLY_EINVAL; \
}

#define WALLY_FN_P3_S(F, N) template <class P1> inline int F(const P1 &p1, uint32_t i321, size_t * written) { \
        return ::N(WALLYP(p1), i321, written); \
}

#define WALLY_FN_P33_A(F, N) template <class P1, class O> inline int F(const P1 &p1, uint32_t i321, uint32_t i322, O * *out) { \
        return ::N(WALLYP(p1), i321, i322, out); \
}

#define WALLY_FN_P6B3(F, N) template <class P1, class I1> inline int F(const P1 &p1, uint64_t i641, const I1 &i1, uint32_t i321) { \
        return ::N(WALLYP(p1), i641, WALLYB(i1), i321); \
}

#define WALLY_FN_P6BB33_B(F, N) template <class P1, class I1, class I2, class O> \
    inline int F(const P1 &p1, uint64_t i641, const I1 &i1, const I2 &i2, uint32_t i321, uint32_t i322, O & out) { \
        return ::N(WALLYP(p1), i641, WALLYB(i1), WALLYB(i2), i321, i322, WALLYO(out)); \
}

#define WALLY_FN_P6BBBBBB3(F, N) template <class P1, class I1, class I2, class I3, class I4, class I5, class I6> \
    inline int F(const P1 &p1, uint64_t i641, const I1 &i1, const I2 &i2, const I3 &i3, const I4& i4, const I5 &i5, const I6 &i6, uint32_t i321) { \
        return ::N(WALLYP(p1), i641, WALLYB(i1), WALLYB(i2), WALLYB(i3), WALLYB(i4), WALLYB(i5), WALLYB(i6), i321); \
}

#define WALLY_FN_PB(F, N) template <class P1, class I1> inline int F(const P1 &p1, const I1 &i1) { \
        return ::N(WALLYP(p1), WALLYB(i1)); \
}

#define WALLY_FN_PBBBBB(F, N) template <class P1, class I1, class I2, class I3, class I4, class I5> \
    inline int F(const P1 &p1, const I1 &i1, const I2 &i2, const I3 &i3, const I4& i4, const I5 &i5) { \
        return ::N(WALLYP(p1), WALLYB(i1), WALLYB(i2), WALLYB(i3), WALLYB(i4), WALLYB(i5)); \
}

#define WALLY_FN_PBBBBBB(F, N) template <class P1, class I1, class I2, class I3, class I4, class I5, class I6> \
    inline int F(const P1 &p1, const I1 &i1, const I2 &i2, const I3 &i3, const I4& i4, const I5 &i5, const I6 &i6) { \
        return ::N(WALLYP(p1), WALLYB(i1), WALLYB(i2), WALLYB(i3), WALLYB(i4), WALLYB(i5), WALLYB(i6)); \
}

#define WALLY_FN_PB33BP3(F, N) template <class P1, class I1, class I2, class P2> inline int F(const P1 &p1, const I1 &i1, uint32_t i321, uint32_t i322, const I2 &i2, const P2 &p2, uint32_t i323) { \
        return ::N(WALLYP(p1), WALLYB(i1), i321, i322, WALLYB(i2), WALLYP(p2), i323); \
}

#define WALLY_FN_B33BPBBBBBB_A(F, N) template <class I1, class I2, class P1, class I3, class I4, class I5, class I6, class I7, class I8, class O> \
    inline int F(const I1 &i1, uint32_t i321, uint32_t i322, const I2 &i2, const P1 &p1, const I3 &i3, \
                 const I4& i4, const I5 &i5, const I6 &i6, const I7& i7, const I8& i8, O * *out) { \
        return ::N(WALLYB(i1), i321, i322, WALLYB(i2), WALLYP(p1), WALLYB(i3), WALLYB(i4), WALLYB(i5), WALLYB(i6), WALLYB(i7), WALLYB(i8), out); \
}

#define WALLY_FN_PB33BPBBBBBB3(F, N) template <class P1, class I1, class I2, class P2, class I3, class I4, class I5, class I6, class I7, class I8> \
    inline int F(const P1 &p1, const I1 &i1, uint32_t i321, uint32_t i322, const I2 &i2, const P2 &p2, \
                 const I3 &i3, const I4& i4, const I5 &i5, const I6 &i6, const I7& i7, const I8& i8, uint32_t i323) { \
        return ::N(WALLYP(p1), WALLYB(i1), i321, i322, WALLYB(i2), WALLYP(p2), WALLYB(i3), WALLYB(i4), WALLYB(i5), WALLYB(i6), WALLYB(i7), WALLYB(i8), i323); \
}

#define WALLY_FN_PB3_A(F, N) template <class P1, class I1, class O> inline int F(const P1 &p1, const I1 &i1, uint32_t i321, O * *out) { \
        return ::N(WALLYP(p1), WALLYB(i1), i321, out); \
}

#define WALLY_FN_PB3_B(F, N) template <class P1, class I1, class O> inline int F(const P1 &p1, const I1 &i1, uint32_t i321, O & out) { \
        return ::N(WALLYP(p1), WALLYB(i1), i321, WALLYO(out)); \
}

#define WALLY_FN_PB3_P(F, N) template <class P1, class I1, class O> inline int F(const P1 &p1, const I1 &i1, uint32_t i321, O * out) { \
        return ::N(WALLYP(p1), WALLYB(i1), i321, out); \
}

#define WALLY_FN_PB_A(F, N) template <class P1, class I1, class O> inline int F(const P1 &p1, const I1 &i1, O * *out) { \
        return ::N(WALLYP(p1), WALLYB(i1), out); \
}

#define WALLY_FN_PP(F, N) template <class P1, class P2> inline int F(const P1 &p1, const P2 &p2) { \
        return ::N(WALLYP(p1), WALLYP(p2)); \
}

#define WALLY_FN_PP3_BS(F, N) template <class P1, class P2, class O> inline int F(const P1 &p1, const P2 &p2, uint32_t i321, O & out, size_t * written = 0) { \
        size_t n; \
        int ret = ::N(WALLYP(p1), WALLYP(p2), i321, WALLYO(out), written ? written : &n); \
        return written || ret != WALLY_OK ? ret : n == static_cast<size_t>(out.size()) ? WALLY_OK : WALLY_EINVAL; \
}

#define WALLY_FN_PP_BS(F, N) template <class P1, class P2, class O> inline int F(const P1 &p1, const P2 &p2, O & out, size_t * written = 0) { \
        size_t n; \
        int ret = ::N(WALLYP(p1), WALLYP(p2), WALLYO(out), written ? written : &n); \
        return written || ret != WALLY_OK ? ret : n == static_cast<size_t>(out.size()) ? WALLY_OK : WALLY_EINVAL; \
}

#define WALLY_FN_PS(F, N) template <class P1> inline int F(const P1 &p1, size_t s1) { \
        return ::N(WALLYP(p1), s1); \
}

#define WALLY_FN_PSB(F, N) template <class P1, class I1> inline int F(const P1 &p1, size_t s1, const I1 &i1) { \
        return ::N(WALLYP(p1), s1, WALLYB(i1)); \
}

#define WALLY_FN_PSP(F, N) template <class P1, class P2> inline int F(const P1 &p1, size_t s1, const P2 &p2) { \
        return ::N(WALLYP(p1), s1, WALLYP(p2)); \
}

#define WALLY_FN_PS_A(F, N) template <class P1, class O> inline int F(const P1 &p1, size_t s1, O * *out) { \
        return ::N(WALLYP(p1), s1, out); \
}

#define WALLY_FN_P_A(F, N) template <class P1, class O> inline int F(const P1 &p1, O * *out) { \
        return ::N(WALLYP(p1), out); \
}

#define WALLY_FN_P_BS(F, N) template <class P1, class O> inline int F(const P1 &p1, O & out, size_t * written = 0) { \
        size_t n; \
        int ret = ::N(WALLYP(p1), WALLYO(out), written ? written : &n); \
        return written || ret != WALLY_OK ? ret : n == static_cast<size_t>(out.size()) ? WALLY_OK : WALLY_EINVAL; \
}

#define WALLY_FN_P_S(F, N) template <class P1> inline int F(const P1 &p1, size_t * written) { \
        return ::N(WALLYP(p1), written); \
}

#define WALLY_FN_P_P(F, N) template <class P1, class O> inline int F(const P1 &p1, O * written) { \
        return ::N(WALLYP(p1), written); \
}

#define WALLY_FN_S_S(F, N) inline int F(size_t s1, size_t * written) { \
        return ::N(s1, written); \
}

WALLY_FN_3(init, wally_init)
WALLY_FN_3(cleanup, wally_cleanup)
WALLY_FN_333_BBBBBA(bip32_key_init_alloc, bip32_key_init_alloc)
WALLY_FN_33SS_A(tx_init_alloc, wally_tx_init_alloc)
WALLY_FN_3_A(tx_witness_stack_init_alloc, wally_tx_witness_stack_init_alloc)
WALLY_FN_6B_A(tx_output_init_alloc, wally_tx_output_init_alloc)
WALLY_FN_B(ec_private_key_verify, wally_ec_private_key_verify)
WALLY_FN_B(ec_public_key_verify, wally_ec_public_key_verify)
WALLY_FN_B(secp_randomize, wally_secp_randomize)
WALLY_FN_B33BP_A(tx_input_init_alloc, wally_tx_input_init_alloc)
WALLY_FN_B33_A(bip32_key_from_parent_alloc, bip32_key_from_parent_alloc)
WALLY_FN_B33_A(bip32_key_from_seed_alloc, bip32_key_from_seed_alloc)
WALLY_FN_B33_A(wif_from_bytes, wally_wif_from_bytes)
WALLY_FN_B33_BS(scriptpubkey_csv_2of2_then_1_from_bytes, wally_scriptpubkey_csv_2of2_then_1_from_bytes)
WALLY_FN_B33_BS(scriptpubkey_csv_2of3_then_2_from_bytes, wally_scriptpubkey_csv_2of3_then_2_from_bytes)
WALLY_FN_B33_BS(scriptpubkey_multisig_from_bytes, wally_scriptpubkey_multisig_from_bytes)
WALLY_FN_B33_P(bip32_key_from_seed, bip32_key_from_seed)
WALLY_FN_B3_A(base58_from_bytes, wally_base58_from_bytes)
WALLY_FN_B3_A(tx_from_bytes, wally_tx_from_bytes)
WALLY_FN_B3_BS(format_bitcoin_message, wally_format_bitcoin_message)
WALLY_FN_B3_BS(script_push_from_bytes, wally_script_push_from_bytes)
WALLY_FN_B3_BS(scriptpubkey_p2pkh_from_bytes, wally_scriptpubkey_p2pkh_from_bytes)
WALLY_FN_B3_BS(scriptpubkey_p2sh_from_bytes, wally_scriptpubkey_p2sh_from_bytes)
WALLY_FN_B3_BS(witness_program_from_bytes, wally_witness_program_from_bytes)
WALLY_FN_BB333_B(scrypt, wally_scrypt)
WALLY_FN_BB3_A(bip38_from_private_key, bip38_from_private_key)
WALLY_FN_BB3_B(aes, wally_aes)
WALLY_FN_BB3_B(bip38_raw_from_private_key, bip38_raw_from_private_key)
WALLY_FN_BB3_B(bip38_raw_to_private_key, bip38_raw_to_private_key)
WALLY_FN_BB3_B(ec_sig_from_bytes, wally_ec_sig_from_bytes)
WALLY_FN_BB3_B(ec_sig_verify, wally_ec_sig_verify)
WALLY_FN_BB3_BS(scriptsig_p2pkh_from_sig, wally_scriptsig_p2pkh_from_sig)
WALLY_FN_BBB3_BS(aes_cbc, wally_aes_cbc)
WALLY_FN_BBB3_BS(scriptsig_multisig_from_bytes, wally_scriptsig_multisig_from_bytes)
WALLY_FN_BB_B(hmac_sha256, wally_hmac_sha256)
WALLY_FN_BB_B(hmac_sha512, wally_hmac_sha512)
WALLY_FN_BB_B(ecdh, wally_ecdh)
WALLY_FN_BP3_A(addr_segwit_from_bytes, wally_addr_segwit_from_bytes)
WALLY_FN_BB_BS(scriptsig_p2pkh_from_der, wally_scriptsig_p2pkh_from_der)
WALLY_FN_B_A(bip32_key_unserialize_alloc, bip32_key_unserialize_alloc)
WALLY_FN_B_A(hex_from_bytes, wally_hex_from_bytes)
WALLY_FN_B_B(ec_public_key_decompress, wally_ec_public_key_decompress)
WALLY_FN_B_B(ec_public_key_from_private_key, wally_ec_public_key_from_private_key)
WALLY_FN_B_B(ec_sig_from_der, wally_ec_sig_from_der)
WALLY_FN_B_B(ec_sig_normalize, wally_ec_sig_normalize)
WALLY_FN_B_B(hash160, wally_hash160)
WALLY_FN_B_B(sha256, wally_sha256)
WALLY_FN_B_B(sha256d, wally_sha256d)
WALLY_FN_B_B(sha512, wally_sha512)
WALLY_FN_B_BS(ec_sig_to_der, wally_ec_sig_to_der)
WALLY_FN_B_P(bip32_key_unserialize, bip32_key_unserialize)
WALLY_FN_B_S(scriptpubkey_get_type, wally_scriptpubkey_get_type)
WALLY_FN_BB33_B(pbkdf2_hmac_sha256, wally_pbkdf2_hmac_sha256)
WALLY_FN_BB33_B(pbkdf2_hmac_sha512, wally_pbkdf2_hmac_sha512)
WALLY_FN_P(bip32_key_free, bip32_key_free)
WALLY_FN_P(get_operations, wally_get_operations)
WALLY_FN_P(set_operations, wally_set_operations)
WALLY_FN_P(tx_free, wally_tx_free)
WALLY_FN_P(tx_input_free, wally_tx_input_free)
WALLY_FN_P(tx_output_free, wally_tx_output_free)
WALLY_FN_P(tx_witness_stack_free, wally_tx_witness_stack_free)
WALLY_FN_P3(tx_witness_stack_add_dummy, wally_tx_witness_stack_add_dummy)
WALLY_FN_P3(tx_witness_stack_set_dummy, wally_tx_witness_stack_set_dummy)
WALLY_FN_P33_P(bip32_key_from_parent, bip32_key_from_parent)
WALLY_FN_P3B(tx_witness_stack_set, wally_tx_witness_stack_set)
WALLY_FN_P3B633_B(tx_get_btc_signature_hash, wally_tx_get_btc_signature_hash)
WALLY_FN_P3BB36333_B(tx_get_signature_hash, wally_tx_get_signature_hash)
WALLY_FN_P3_A(bip32_key_to_base58, bip32_key_to_base58)
WALLY_FN_P3_A(tx_from_hex, wally_tx_from_hex)
WALLY_FN_P3_A(tx_to_hex, wally_tx_to_hex)
WALLY_FN_P3_B(bip32_key_serialize, bip32_key_serialize)
WALLY_FN_P3_B(wif_to_bytes, wally_wif_to_bytes)
WALLY_FN_P3_BS(base58_to_bytes, wally_base58_to_bytes)
WALLY_FN_P3_BS(tx_to_bytes, wally_tx_to_bytes)
WALLY_FN_P3_BS(wif_to_public_key, wally_wif_to_public_key)
WALLY_FN_P3_S(tx_get_length, wally_tx_get_length)
WALLY_FN_P33_A(wif_to_address, wally_wif_to_address)
WALLY_FN_P6B3(tx_add_raw_output, wally_tx_add_raw_output)
WALLY_FN_PB(tx_witness_stack_add, wally_tx_witness_stack_add)
WALLY_FN_PB33BP3(tx_add_raw_input, wally_tx_add_raw_input)
WALLY_FN_PB3_A(bip32_key_from_parent_path_alloc, bip32_key_from_parent_path_alloc)
WALLY_FN_PB3_B(bip38_to_private_key, bip38_to_private_key)
WALLY_FN_PB3_P(bip32_key_from_parent_path, bip32_key_from_parent_path)
WALLY_FN_PB_A(bip39_mnemonic_from_bytes, bip39_mnemonic_from_bytes)
WALLY_FN_PP(bip39_mnemonic_validate, bip39_mnemonic_validate)
WALLY_FN_PP(tx_add_input, wally_tx_add_input)
WALLY_FN_PP(tx_add_output, wally_tx_add_output)
WALLY_FN_PP3_BS(addr_segwit_to_bytes, wally_addr_segwit_to_bytes)
WALLY_FN_PP_BS(bip39_mnemonic_to_bytes, bip39_mnemonic_to_bytes)
WALLY_FN_PP_BS(bip39_mnemonic_to_seed, bip39_mnemonic_to_seed)
WALLY_FN_PS(tx_remove_input, wally_tx_remove_input)
WALLY_FN_PS(tx_remove_output, wally_tx_remove_output)
WALLY_FN_PSB(tx_set_input_script, wally_tx_set_input_script)
WALLY_FN_PSP(tx_set_input_witness, wally_tx_set_input_witness)
WALLY_FN_PS_A(bip39_get_word, bip39_get_word)
WALLY_FN_P_A(bip32_key_from_base58_alloc, bip32_key_from_base58_alloc)
WALLY_FN_P_A(bip39_get_languages, bip39_get_languages)
WALLY_FN_P_A(bip39_get_wordlist, bip39_get_wordlist)
WALLY_FN_P_BS(hex_to_bytes, wally_hex_to_bytes)
WALLY_FN_P_S(base58_get_length, wally_base58_get_length)
WALLY_FN_P_S(wif_is_uncompressed, wally_wif_is_uncompressed)
WALLY_FN_P_S(tx_get_vsize, wally_tx_get_vsize)
WALLY_FN_P_S(tx_get_weight, wally_tx_get_weight)
WALLY_FN_P_S(tx_get_witness_count, wally_tx_get_witness_count)
WALLY_FN_P_P(bip32_key_from_base58, bip32_key_from_base58)
WALLY_FN_P_P(tx_get_total_output_satoshi, wally_tx_get_total_output_satoshi)
WALLY_FN_S_S(tx_vsize_from_weight, wally_tx_vsize_from_weight)

inline struct secp256k1_context_struct *get_secp_context() {
    return ::wally_get_secp_context();
}

inline int free_string(char *str) {
    return ::wally_free_string(str);
}

inline int clear(void *p, size_t n) {
    return ::wally_bzero(p, n);
}

template<typename O> inline int clear(O& out) {
    return ::wally_bzero(out.data(), out.size());
}

inline bool is_elements_build()
{
    uint64_t ret = 0;
    ::wally_is_elements_build(&ret);
    return ret != 0;
}

#ifdef BUILD_ELEMENTS
WALLY_FN_PBBBBBB(tx_elements_input_issuance_set, wally_tx_elements_input_issuance_set)
WALLY_FN_P(tx_elements_input_issuance_free, wally_tx_elements_input_issuance_free)
WALLY_FN_B33BPBBBBBB_A(tx_elements_input_init_alloc, wally_tx_elements_input_init_alloc)
WALLY_FN_PBBBBB(tx_elements_output_commitment_set, wally_tx_elements_output_commitment_set)
WALLY_FN_P(tx_elements_output_commitment_free, wally_tx_elements_output_commitment_free)
WALLY_FN_6BBBBBB_A(tx_elements_output_init_alloc, wally_tx_elements_output_init_alloc)
WALLY_FN_PB33BPBBBBBB3(tx_add_elements_raw_input, wally_tx_add_elements_raw_input)
WALLY_FN_P6BBBBBB3(tx_add_elements_raw_output, wally_tx_add_elements_raw_output)
WALLY_FN_P_S(tx_is_elements, wally_tx_is_elements)
WALLY_FN_6_B(tx_confidential_value_from_satoshi, wally_tx_confidential_value_from_satoshi)
WALLY_FN_P6BB33_B(tx_get_elements_signature_hash, wally_tx_get_elements_signature_hash)
WALLY_FN_B3B_B(tx_elements_issuance_generate_entropy, wally_tx_elements_issuance_generate_entropy)
WALLY_FN_B_B(tx_elements_issuance_calculate_asset, wally_tx_elements_issuance_calculate_asset)
WALLY_FN_B3_B(tx_elements_issuance_calculate_reissuance_token, wally_tx_elements_issuance_calculate_reissuance_token)
#endif /* BUILD_ELEMENTS */

#undef WALLYB
#undef WALLYO

} /* namespace wally */

#endif /* LIBWALLY_CORE_WALLY_HPP */
