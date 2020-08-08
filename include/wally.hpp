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
#include <wally_psbt.h>
#include <wally_script.h>
#include <wally_symmetric.h>
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

#define WALLY_FN_333BBBBB_A(F, N) template <class I1, class I2, class I3, class I4, class I5, class O> inline int F(uint32_t i321, uint32_t i322, uint32_t i323, const I1 &i1, const I2 &i2, const I3 &i3, const I4 &i4, const I5 &i5, O * *out) { \
        return ::N(i321, i322, i323, WALLYB(i1), WALLYB(i2), WALLYB(i3), WALLYB(i4), WALLYB(i5), out); \
}

#define WALLY_FN_33SS_A(F, N) template <class O> inline int F(uint32_t i321, uint32_t i322, size_t s1, size_t s2, O * *out) { \
        return ::N(i321, i322, s1, s2, out); \
}

#define WALLY_FN_S_A(F, N) template <class O> inline int F(size_t s1, O * *out) { \
        return ::N(s1, out); \
}

#define WALLY_FN_3SSS_A(F, N) template <class O> inline int F(uint32_t i321, size_t s1, size_t s2, size_t s3, O * *out) { \
        return ::N(i321, s1, s2, s3, out); \
}

#define WALLY_FN_SSSS_S(F, N) inline int F(size_t s1, size_t s2, size_t s3, size_t s4, size_t * written = 0) { \
        return ::N(s1, s2, s3, s4, written); \
}

#define WALLY_FN_6_B(F, N) template <class O> inline int F(uint64_t i641, O & out) { \
        return ::N(i641, WALLYO(out)); \
}

#define WALLY_FN_6B_A(F, N) template <class I1, class O> inline int F(uint64_t i641, const I1 &i1, O * *out) { \
        return ::N(i641, WALLYB(i1), out); \
}

#define WALLY_FN_6B_P(F, N) template <class I1, class O> inline int F(uint64_t i641, const I1 &i1, O *out) { \
        return ::N(i641, WALLYB(i1), out); \
}

#define WALLY_FN_BBBBBB_A(F, N) template <class I1, class I2, class I3, class I4, class I5, class I6, class O> \
    inline int F(const I1 &i1, const I2 &i2, const I3 &i3, const I4& i4, const I5 &i5, const I6 &i6, O * *out) { \
        return ::N(WALLYB(i1), WALLYB(i2), WALLYB(i3), WALLYB(i4), WALLYB(i5), WALLYB(i6), out); \
}

#define WALLY_FN_BBBBBB_P(F, N) template <class I1, class I2, class I3, class I4, class I5, class I6, class O> \
    inline int F(const I1 &i1, const I2 &i2, const I3 &i3, const I4& i4, const I5 &i5, const I6 &i6, O *out) { \
        return ::N(WALLYB(i1), WALLYB(i2), WALLYB(i3), WALLYB(i4), WALLYB(i5), WALLYB(i6), out); \
}

#define WALLY_FN_BB_A(F, N) template <class I1, class I2, class O> \
    inline int F(const I1 &i1, const I2 &i2, O * *out) { \
        return ::N(WALLYB(i1), WALLYB(i2), out); \
}

#define WALLY_FN_BBB3_A(F, N) template <class I1, class I2, class I3, class O> \
    inline int F(const I1 &i1, const I2 &i2, const I3 &i3, uint32_t i321, O * *out) { \
        return ::N(WALLYB(i1), WALLYB(i2), WALLYB(i3), i321, out); \
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

#define WALLY_FN_BB3B(F, N) template <class I1, class I2, class I3> inline int F(const I1 &i1, const I2 &i2, uint32_t i321, const I3 &i3) { \
        return ::N(WALLYB(i1), WALLYB(i2), i321, WALLYB(i3)); \
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

#define WALLY_FN_6BB_B(F, N) template <class I1, class I2, class O> inline int F(uint64_t i641, const I1 &i1, const I2 &i2, O & out) { \
        return ::N(i641, WALLYB(i1), WALLYB(i2), WALLYO(out)); \
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

#define WALLY_FN_B_6(F, N) template <class I> inline int F(const I &i1, uint64_t *out) { \
        return ::N(WALLYB(i1), out); \
}

#define WALLY_FN_BSBB_B(F, N) template <class I1, class I2, class I3, class O> inline int F(const I1 &i1, size_t s1, const I2& i2, const I3& i3, O & out) { \
        return ::N(WALLYB(i1), s1, WALLYB(i2), WALLYB(i3), WALLYO(out)); \
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

#define WALLY_FN_PS3(F, N) template <class P1> inline int F(const P1 &p1, size_t s1, uint32_t i321) { \
        return ::N(WALLYP(p1), s1, i321); \
}

#define WALLY_FN_P6(F, N) template <class P1> inline int F(const P1 &p1, uint64_t i641) { \
        return ::N(WALLYP(p1), i641); \
}

#define WALLY_FN_P33(F, N) template <class P1> inline int F(const P1 &p1, uint32_t i321, uint32_t i322) { \
        return ::N(WALLYP(p1), i321, i322); \
}

#define WALLY_FN_P33P(F, N) template <class P1, class P2> inline int F(const P1 &p1, uint32_t i321, uint32_t i322, const P2 &p2) { \
        return ::N(WALLYP(p1), i321, i322, WALLYP(p2)); \
}

#define WALLY_FN_P33_P(F, N) template <class P1, class O> inline int F(const P1 &p1, uint32_t i321, uint32_t i322, O * out) { \
        return ::N(WALLYP(p1), i321, i322, out); \
}

#define WALLY_FN_P3B_A(F, N) template <class P1, class I1, class O> inline int F(const P1 &p1, uint32_t i321, const I1 &i1, O * * out) { \
        return ::N(WALLYP(p1), i321, WALLYB(i1), out); \
}

#define WALLY_FN_PSB633_B(F, N) template <class P1, class I1, class O> inline int F(const P1 &p1, size_t s1, const I1 &i1, uint64_t i641, uint32_t i321, uint32_t i322, O & out) { \
        return ::N(WALLYP(p1), s1, WALLYB(i1), i641, i321, i322, WALLYO(out)); \
}

#define WALLY_FN_PSBB36333_B(F, N) \
    template <class P1, class I1, class I2, class O> \
    inline int F(const P1 &p1, size_t s1, const I1 &i1, const I2 &i2,  uint32_t i321, uint64_t i641, uint32_t i322, uint32_t i323, uint32_t i324, O & out) { \
        return ::N(WALLYP(p1), s1, WALLYB(i1), WALLYB(i2), i321, i641, i322, i323, i324, WALLYO(out)); \
    }

#define WALLY_FN_P3_A(F, N) template <class P1, class O> inline int F(const P1 &p1, uint32_t i321, O * *out) { \
        return ::N(WALLYP(p1), i321, out); \
}

#define WALLY_FN_P3_B(F, N) template <class P1, class O> inline int F(const P1 &p1, uint32_t i321, O & out) { \
        return ::N(WALLYP(p1), i321, WALLYO(out)); \
}

#define WALLY_FN_P33_B(F, N) template <class P1, class O> inline int F(const P1 &p1, uint32_t i321, uint32_t i322, O & out) { \
        return ::N(WALLYP(p1), i321, i322, WALLYO(out)); \
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

#define WALLY_FN_PSBB33_B(F, N) template <class P1, class I1, class I2, class O> \
    inline int F(const P1 &p1, size_t s1, const I1 &i1, const I2 &i2, uint32_t i321, uint32_t i322, O & out) { \
        return ::N(WALLYP(p1), s1, WALLYB(i1), WALLYB(i2), i321, i322, WALLYO(out)); \
}

#define WALLY_FN_P3BBBBBB3(F, N) template <class P1, class I1, class I2, class I3, class I4, class I5, class I6> \
    inline int F(const P1 &p1, uint32_t i321, const I1 &i1, const I2 &i2, const I3 &i3, const I4& i4, const I5 &i5, const I6 &i6, uint32_t i322) { \
        return ::N(WALLYP(p1), i321, WALLYB(i1), WALLYB(i2), WALLYB(i3), WALLYB(i4), WALLYB(i5), WALLYB(i6), i322); \
}

#define WALLY_FN_PBBBBBB3(F, N) template <class P1, class I1, class I2, class I3, class I4, class I5, class I6> \
    inline int F(const P1 &p1, const I1 &i1, const I2 &i2, const I3 &i3, const I4& i4, const I5 &i5, const I6 &i6, uint32_t i321) { \
        return ::N(WALLYP(p1), WALLYB(i1), WALLYB(i2), WALLYB(i3), WALLYB(i4), WALLYB(i5), WALLYB(i6), i321); \
}

#define WALLY_FN_PB(F, N) template <class P1, class I1> inline int F(const P1 &p1, const I1 &i1) { \
        return ::N(WALLYP(p1), WALLYB(i1)); \
}

#define WALLY_FN_PB3(F, N) template <class P1, class I1> inline int F(const P1 &p1, const I1 &i1, uint32_t i321) { \
        return ::N(WALLYP(p1), WALLYB(i1), i321); \
}

#define WALLY_FN_PBB(F, N) template <class P1, class I1, class I2> \
    inline int F(const P1 &p1, const I1 &i1, const I2 &i2) { return ::N(WALLYP(p1), WALLYB(i1), WALLYB(i2)); }

#define WALLY_FN_PBBB(F, N) template <class P1, class I1, class I2, class I3> \
    inline int F(const P1 &p1, const I1 &i1, const I2 &i2, const I3 &i3) { \
        return ::N(WALLYP(p1), WALLYB(i1), WALLYB(i2), WALLYB(i3)); \
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

#define WALLY_FN_PB33BPBBBBBBP3(F, N) template <class P1, class I1, class I2, class P2, class I3, class I4, class I5, class I6, class I7, class I8, class P3> \
    inline int F(const P1 &p1, const I1 &i1, uint32_t i321, uint32_t i322, const I2 &i2, const P2 &p2, \
                 const I3 &i3, const I4& i4, const I5 &i5, const I6 &i6, const I7& i7, const I8& i8, const P3& p3, uint32_t i323) { \
        return ::N(WALLYP(p1), WALLYB(i1), i321, i322, WALLYB(i2), WALLYP(p2), WALLYB(i3), WALLYB(i4), WALLYB(i5), WALLYB(i6), WALLYB(i7), WALLYB(i8), WALLYP(p3), i323); \
}

#define WALLY_FN_P3B33BPBBBBBBP3(F, N) template <class P1, class I1, class I2, class P2, class I3, class I4, class I5, class I6, class I7, class I8, class P3> \
    inline int F(const P1 &p1, uint32_t i321, const I1 &i1, uint32_t i322, uint32_t i323, const I2 &i2, const P2 &p2, \
                 const I3 &i3, const I4& i4, const I5 &i5, const I6 &i6, const I7& i7, const I8& i8, const P3& p3, uint32_t i324) { \
        return ::N(WALLYP(p1), i321, WALLYB(i1), i322, i323, WALLYB(i2), WALLYP(p2), WALLYB(i3), WALLYB(i4), WALLYB(i5), WALLYB(i6), WALLYB(i7), WALLYB(i8), WALLYP(p3), i324); \
}

#define WALLY_FN_P3B33BP3(F, N) template <class P1, class I1, class I2, class P2> \
    inline int F(const P1 &p1, uint32_t i321, const I1 &i1, uint32_t i322, uint32_t i323, const I2 &i2, const P2 &p2, uint32_t i324) { \
        return ::N(WALLYP(p1), i321, WALLYB(i1), i322, i323, WALLYB(i2), WALLYP(p2), i324); \
}

#define WALLY_FN_P36B3(F, N) template <class P1, class I1> \
    inline int F(const P1 &p1, uint32_t i321, uint64_t i641, const I1 &i1, uint32_t i322) { \
        return ::N(WALLYP(p1), i321, i641, WALLYB(i1), i322); \
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

#define WALLY_FN_P3_P(F, N) template <class P1, class P2, class O> inline int F(const P1 &p1, uint32_t i321, O * out) { \
        return ::N(WALLYP(p1), i321, out); \
}

#define WALLY_FN_PB_A(F, N) template <class P1, class I1, class O> inline int F(const P1 &p1, const I1 &i1, O * *out) { \
        return ::N(WALLYP(p1), WALLYB(i1), out); \
}

#define WALLY_FN_PB_S(F, N) template <class P1, class I1, class O> inline int F(const P1 &p1, const I1 &i1, size_t * written) { \
        return ::N(WALLYP(p1), WALLYB(i1), written); \
}

#define WALLY_FN_PP(F, N) template <class P1, class P2> inline int F(const P1 &p1, const P2 &p2) { \
        return ::N(WALLYP(p1), WALLYP(p2)); \
}

#define WALLY_FN_PPP_A(F, N) template <class P1, class P2, class P3, class O> inline int F(const P1 &p1, const P2 &p2, const P3& p3, O * *out) { \
        return ::N(WALLYP(p1), WALLYP(p2), WALLYP(p3), out); \
}

#define WALLY_FN_PP3_A(F, N) template <class P1, class P2, class O> inline int F(const P1 &p1, const P2 &p2, uint32_t i321, O * *out) { \
        return ::N(WALLYP(p1), WALLYP(p2), i321, out); \
}

#define WALLY_FN_PPPB_A(F, N) template <class P1, class P2, class P3, class I1, class O> \
    inline int F(const P1 &p1, const P2 &p2, const P3& p3, const I1& i1, O * *out) { \
        return ::N(WALLYP(p1), WALLYP(p2), WALLYP(p3), WALLYB(i1), out); \
}

#define WALLY_FN_PP3_BS(F, N) template <class P1, class P2, class O> inline int F(const P1 &p1, const P2 &p2, uint32_t i321, O & out, size_t * written = 0) { \
        size_t n; \
        int ret = ::N(WALLYP(p1), WALLYP(p2), i321, WALLYO(out), written ? written : &n); \
        return written || ret != WALLY_OK ? ret : n == static_cast<size_t>(out.size()) ? WALLY_OK : WALLY_EINVAL; \
}

#define WALLY_FN_BBSBBB_BS(F, N) template <class I1, class I2, class I3, class I4, class I5, class O>  \
    inline int F(const I1 &i1, const I2 &i2, size_t s1, const I3& i3, const I4& i4, const I5& i5, O & out, size_t * written = 0) { \
        size_t n; \
        int ret = ::N(WALLYB(i1), WALLYB(i2), s1, WALLYB(i3), WALLYB(i4), WALLYB(i5), WALLYO(out), written ? written : &n); \
        return written || ret != WALLY_OK ? ret : n == static_cast<size_t>(out.size()) ? WALLY_OK : WALLY_EINVAL; \
}

#define WALLY_FN_BBBB3_BS(F, N) template <class I1, class I2, class I3, class I4, class O>  \
    inline int F(const I1 &i1, const I2 &i2, const I3& i3, const I4& i4, uint32_t i321, O & out, size_t * written = 0) { \
        size_t n; \
        int ret = ::N(WALLYB(i1), WALLYB(i2), WALLYB(i3), WALLYB(i4), i321, WALLYO(out), written ? written : &n); \
        return written || ret != WALLY_OK ? ret : n == static_cast<size_t>(out.size()) ? WALLY_OK : WALLY_EINVAL; \
}

#define WALLY_FN_BBBBBBB_BS(F, N) template <class I1, class I2, class I3, class I4, class I5, class I6, class I7, class O>  \
    inline int F(const I1 &i1, const I2 &i2, const I3& i3, const I4& i4, const I5& i5, const I6& i6, const I7& i7, O & out, size_t * written = 0) { \
        size_t n; \
        int ret = ::N(WALLYB(i1), WALLYB(i2), WALLYB(i3), WALLYB(i4), WALLYB(i5), WALLYB(i6), WALLYB(i7), WALLYO(out), written ? written : &n); \
        return written || ret != WALLY_OK ? ret : n == static_cast<size_t>(out.size()) ? WALLY_OK : WALLY_EINVAL; \
}

#define WALLY_FN_6BBBBBBBB6II_BS(F, N) template <class I1, class I2, class I3, class I4, class I5, class I6, class I7, class I8, class O>  \
    inline int F(uint64_t i641, const I1 &i1, const I2 &i2, const I3& i3, const I4& i4, const I5& i5, const I6& i6, const I7& i7, const I8& i8, uint64_t i642, int i321, int i322, O & out, size_t * written = 0) { \
        size_t n; \
        int ret = ::N(i641, WALLYB(i1), WALLYB(i2), WALLYB(i3), WALLYB(i4), WALLYB(i5), WALLYB(i6), WALLYB(i7), WALLYB(i8), i642, i321, i322, WALLYO(out), written ? written : &n); \
        return written || ret != WALLY_OK ? ret : n == static_cast<size_t>(out.size()) ? WALLY_OK : WALLY_EINVAL; \
}

#define WALLY_FN_BBBBB_BBB6(F, N) template <class I1, class I2, class I3, class I4, class I5, class O1, class O2, class O3>  \
    inline int F(const I1 &i1, const I2 &i2, size_t s1, const I3& i3, const I4& i4, const I5& i5, O1& out1, O2& out2, O3& out3, uint64_t *out) { \
        return ::N(WALLYB(i1), WALLYB(i2), WALLYB(i3), WALLYB(i4), WALLYB(i5), WALLYO(out1), WALLYO(out2), WALLYO(out3), out); \
}

#define WALLY_FN_BBBBBB_BBB6(F, N) template <class I1, class I2, class I3, class I4, class I5, class I6, class O1, class O2, class O3>  \
    inline int F(const I1 &i1, const I2 &i2, size_t s1, const I3& i3, const I4& i4, const I5& i5, const I6& i6, O1& out1, O2& out2, O3& out3, uint64_t *out) { \
        return ::N(WALLYB(i1), WALLYB(i2), WALLYB(i3), WALLYB(i4), WALLYB(i5), WALLYB(i6), WALLYO(out1), WALLYO(out2), WALLYO(out3), out); \
}

#define WALLY_FN_PP_B(F, N) template <class P1, class P2, class O> inline int F(const P1 &p1, const P2 &p2, O & out) { \
        return ::N(WALLYP(p1), WALLYP(p2), WALLYO(out)); \
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

#define WALLY_FN__A(F, N) template <class O> inline int F(O **out) { return ::N(out); }

#define WALLY_FN__S(F, N) inline int F(size_t *written) { return ::N(written); }

#define WALLY_FN_P_A(F, N) template <class P1, class O> inline int F(const P1 &p1, O * *out) { \
        return ::N(WALLYP(p1), out); \
}

#define WALLY_FN_P_B(F, N) template <class P1, class O> inline int F(const P1 &p1, O & out) { \
        return ::N(WALLYP(p1), WALLYO(out)); \
}

#define WALLY_FN_P_BS(F, N) template <class P1, class O> inline int F(const P1 &p1, O & out, size_t * written = 0) { \
        size_t n; \
        int ret = ::N(WALLYP(p1), WALLYO(out), written ? written : &n); \
        return written || ret != WALLY_OK ? ret : n == static_cast<size_t>(out.size()) ? WALLY_OK : WALLY_EINVAL; \
}

#define WALLY_FN_P_S(F, N) template <class P1> inline int F(const P1 &p1, size_t * written) { \
        return ::N(WALLYP(p1), written); \
}

#define WALLY_FN_P_P(F, N) template <class P1, class O> inline int F(const P1 &p1, O * out) { \
        return ::N(WALLYP(p1), out); \
}

#define WALLY_FN_S_S(F, N) inline int F(size_t s1, size_t * written) { \
        return ::N(s1, written); \
}

WALLY_FN_3(cleanup, wally_cleanup)
WALLY_FN_3(init, wally_init)
WALLY_FN_333BBBBB_A(bip32_key_init_alloc, bip32_key_init_alloc)
WALLY_FN_33SS_A(tx_init_alloc, wally_tx_init_alloc)
WALLY_FN_3SSS_A(psbt_init_alloc, wally_psbt_init_alloc)
WALLY_FN_6B_A(tx_output_init_alloc, wally_tx_output_init_alloc)
WALLY_FN_6B_P(tx_output_init, wally_tx_output_init)
WALLY_FN_B(ec_private_key_verify, wally_ec_private_key_verify)
WALLY_FN_B(ec_public_key_verify, wally_ec_public_key_verify)
WALLY_FN_B(secp_randomize, wally_secp_randomize)
WALLY_FN_B33BP_A(tx_input_init_alloc, wally_tx_input_init_alloc)
WALLY_FN_B33_A(bip32_key_from_seed_alloc, bip32_key_from_seed_alloc)
WALLY_FN_B33_A(wif_from_bytes, wally_wif_from_bytes)
WALLY_FN_B33_BS(scriptpubkey_csv_2of2_then_1_from_bytes, wally_scriptpubkey_csv_2of2_then_1_from_bytes)
WALLY_FN_B33_BS(scriptpubkey_csv_2of3_then_2_from_bytes, wally_scriptpubkey_csv_2of3_then_2_from_bytes)
WALLY_FN_B33_BS(scriptpubkey_multisig_from_bytes, wally_scriptpubkey_multisig_from_bytes)
WALLY_FN_B33_P(bip32_key_from_seed, bip32_key_from_seed)
WALLY_FN_B3B_B(symmetric_key_from_parent, wally_symmetric_key_from_parent)
WALLY_FN_B3_A(base58_from_bytes, wally_base58_from_bytes)
WALLY_FN_B3_A(scriptpubkey_to_address, wally_scriptpubkey_to_address)
WALLY_FN_B3_A(tx_from_bytes, wally_tx_from_bytes)
WALLY_FN_B3_BS(format_bitcoin_message, wally_format_bitcoin_message)
WALLY_FN_B3_BS(script_push_from_bytes, wally_script_push_from_bytes)
WALLY_FN_B3_BS(scriptpubkey_op_return_from_bytes, wally_scriptpubkey_op_return_from_bytes)
WALLY_FN_B3_BS(scriptpubkey_p2pkh_from_bytes, wally_scriptpubkey_p2pkh_from_bytes)
WALLY_FN_B3_BS(scriptpubkey_p2sh_from_bytes, wally_scriptpubkey_p2sh_from_bytes)
WALLY_FN_B3_BS(witness_program_from_bytes, wally_witness_program_from_bytes)
WALLY_FN_BB333_B(scrypt, wally_scrypt)
WALLY_FN_BB33_B(pbkdf2_hmac_sha256, wally_pbkdf2_hmac_sha256)
WALLY_FN_BB33_B(pbkdf2_hmac_sha512, wally_pbkdf2_hmac_sha512)
WALLY_FN_BB3B(ec_sig_verify, wally_ec_sig_verify)
WALLY_FN_BB3_A(bip38_from_private_key, bip38_from_private_key)
WALLY_FN_BB3_A(witness_p2wpkh_from_sig, wally_witness_p2wpkh_from_sig)
WALLY_FN_BB3_B(aes, wally_aes)
WALLY_FN_BB3_B(bip38_raw_from_private_key, bip38_raw_from_private_key)
WALLY_FN_BB3_B(bip38_raw_to_private_key, bip38_raw_to_private_key)
WALLY_FN_BB3_B(ec_sig_from_bytes, wally_ec_sig_from_bytes)
WALLY_FN_BB3_BS(scriptsig_p2pkh_from_sig, wally_scriptsig_p2pkh_from_sig)
WALLY_FN_BBB3_A(witness_multisig_from_bytes, wally_witness_multisig_from_bytes)
WALLY_FN_BBB3_BS(aes_cbc, wally_aes_cbc)
WALLY_FN_BBB3_BS(scriptsig_multisig_from_bytes, wally_scriptsig_multisig_from_bytes)
WALLY_FN_BB_A(witness_p2wpkh_from_der, wally_witness_p2wpkh_from_der)
WALLY_FN_BB_B(ec_sig_to_public_key, wally_ec_sig_to_public_key)
WALLY_FN_BB_B(ecdh, wally_ecdh)
WALLY_FN_BB_B(hmac_sha256, wally_hmac_sha256)
WALLY_FN_BB_B(hmac_sha512, wally_hmac_sha512)
WALLY_FN_BB_BS(scriptsig_p2pkh_from_der, wally_scriptsig_p2pkh_from_der)
WALLY_FN_BP3_A(addr_segwit_from_bytes, wally_addr_segwit_from_bytes)
WALLY_FN_B_A(bip32_key_unserialize_alloc, bip32_key_unserialize_alloc)
WALLY_FN_B_A(hex_from_bytes, wally_hex_from_bytes)
WALLY_FN_B_A(psbt_from_bytes, wally_psbt_from_bytes)
WALLY_FN_B_B(ec_public_key_decompress, wally_ec_public_key_decompress)
WALLY_FN_B_B(ec_public_key_from_private_key, wally_ec_public_key_from_private_key)
WALLY_FN_B_B(ec_public_key_negate, wally_ec_public_key_negate)
WALLY_FN_B_B(ec_sig_from_der, wally_ec_sig_from_der)
WALLY_FN_B_B(ec_sig_normalize, wally_ec_sig_normalize)
WALLY_FN_B_B(hash160, wally_hash160)
WALLY_FN_B_B(sha256, wally_sha256)
WALLY_FN_B_B(sha256_midstate, wally_sha256_midstate)
WALLY_FN_B_B(sha256d, wally_sha256d)
WALLY_FN_B_B(sha512, wally_sha512)
WALLY_FN_B_B(symmetric_key_from_seed, wally_symmetric_key_from_seed)
WALLY_FN_B_BS(ec_sig_to_der, wally_ec_sig_to_der)
WALLY_FN_B_P(bip32_key_unserialize, bip32_key_unserialize)
WALLY_FN_B_S(bip38_raw_get_flags, bip38_raw_get_flags)
WALLY_FN_B_S(scriptpubkey_get_type, wally_scriptpubkey_get_type)
WALLY_FN_P(bip32_key_free, bip32_key_free)
WALLY_FN_P(bip32_key_strip_private_key, bip32_key_strip_private_key)
WALLY_FN_P(get_operations, wally_get_operations)
WALLY_FN_P(psbt_free, wally_psbt_free)
WALLY_FN_P(set_operations, wally_set_operations)
WALLY_FN_P(tx_free, wally_tx_free)
WALLY_FN_P(tx_input_free, wally_tx_input_free)
WALLY_FN_P(tx_output_free, wally_tx_output_free)
WALLY_FN_P(tx_witness_stack_free, wally_tx_witness_stack_free)
WALLY_FN_P(map_free, wally_map_free)
WALLY_FN_P3(map_sort, wally_map_sort)
WALLY_FN_P3(psbt_input_set_sighash, wally_psbt_input_set_sighash)
WALLY_FN_P3(psbt_remove_input, wally_psbt_remove_input)
WALLY_FN_P3(psbt_remove_output, wally_psbt_remove_output)
WALLY_FN_P3(tx_witness_stack_add_dummy, wally_tx_witness_stack_add_dummy)
WALLY_FN_P33_A(bip32_key_from_parent_alloc, bip32_key_from_parent_alloc)
WALLY_FN_P33_A(bip32_key_to_address, wally_bip32_key_to_address)
WALLY_FN_P33_A(wif_to_address, wally_wif_to_address)
WALLY_FN_P33_B(wif_to_bytes, wally_wif_to_bytes)
WALLY_FN_P33_P(bip32_key_from_parent, bip32_key_from_parent)
WALLY_FN_P33P(psbt_add_input_at, wally_psbt_add_input_at)
WALLY_FN_P33P(psbt_add_output_at, wally_psbt_add_output_at)
WALLY_FN_P36B3(tx_add_raw_output_at, wally_tx_add_raw_output_at)
WALLY_FN_P3B33BP3(tx_add_raw_input_at, wally_tx_add_raw_input_at)
WALLY_FN_P3_A(bip32_key_to_base58, bip32_key_to_base58)
WALLY_FN_P3_A(psbt_clone_alloc, wally_psbt_clone_alloc)
WALLY_FN_P3_A(psbt_to_base64, wally_psbt_to_base64)
WALLY_FN_P3_A(tx_clone_alloc, wally_tx_clone_alloc)
WALLY_FN_P3_A(tx_from_hex, wally_tx_from_hex)
WALLY_FN_P3_A(tx_to_hex, wally_tx_to_hex)
WALLY_FN_P3_B(bip32_key_serialize, bip32_key_serialize)
WALLY_FN_P3_BS(address_to_scriptpubkey, wally_address_to_scriptpubkey)
WALLY_FN_P3_BS(base58_to_bytes, wally_base58_to_bytes)
WALLY_FN_P3_BS(psbt_to_bytes, wally_psbt_to_bytes)
WALLY_FN_P3_BS(tx_to_bytes, wally_tx_to_bytes)
WALLY_FN_P3_BS(wif_to_public_key, wally_wif_to_public_key)
WALLY_FN_P3_S(psbt_get_length, wally_psbt_get_length)
WALLY_FN_P3_S(tx_get_length, wally_tx_get_length)
WALLY_FN_P3_P(tx_add_input_at, wally_tx_add_input_at)
WALLY_FN_P3_P(tx_add_output_at, wally_tx_add_output_at)
WALLY_FN_P6B3(tx_add_raw_output, wally_tx_add_raw_output)
WALLY_FN_PB(psbt_input_set_final_scriptsig, wally_psbt_input_set_final_scriptsig)
WALLY_FN_PB(psbt_input_set_redeem_script, wally_psbt_input_set_redeem_script)
WALLY_FN_PB(psbt_input_set_witness_script, wally_psbt_input_set_witness_script)
WALLY_FN_PB(psbt_output_set_redeem_script, wally_psbt_output_set_redeem_script)
WALLY_FN_PB(psbt_output_set_witness_script, wally_psbt_output_set_witness_script)
WALLY_FN_PB(tx_witness_stack_add, wally_tx_witness_stack_add)
WALLY_FN_PB3(psbt_sign, wally_psbt_sign)
WALLY_FN_PB33BP3(tx_add_raw_input, wally_tx_add_raw_input)
WALLY_FN_PB3_A(bip32_key_from_parent_path_alloc, bip32_key_from_parent_path_alloc)
WALLY_FN_PB3_B(bip38_to_private_key, bip38_to_private_key)
WALLY_FN_PB3_P(bip32_key_from_parent_path, bip32_key_from_parent_path)
WALLY_FN_PBB(map_add, wally_map_add)
WALLY_FN_PBB(psbt_input_add_signature, wally_psbt_input_add_signature)
WALLY_FN_PBBB(map_add_keypath_item, wally_map_add_keypath_item)
WALLY_FN_PBBB(psbt_input_add_keypath_item, wally_psbt_input_add_keypath_item)
WALLY_FN_PBBB(psbt_output_add_keypath_item, wally_psbt_output_add_keypath_item)
WALLY_FN_PB_A(bip39_mnemonic_from_bytes, bip39_mnemonic_from_bytes)
WALLY_FN_PB_S(psbt_input_find_keypath, wally_psbt_input_find_keypath)
WALLY_FN_PB_S(psbt_input_find_signature, wally_psbt_input_find_signature)
WALLY_FN_PB_S(psbt_input_find_unknown, wally_psbt_input_find_unknown)
WALLY_FN_PB_S(psbt_output_find_keypath, wally_psbt_output_find_keypath)
WALLY_FN_PB_S(psbt_output_find_unknown, wally_psbt_output_find_unknown)
WALLY_FN_PB_S(map_find, wally_map_find)
WALLY_FN_PP(bip39_mnemonic_validate, bip39_mnemonic_validate)
WALLY_FN_PP(psbt_combine, wally_psbt_combine)
WALLY_FN_PP(psbt_input_set_final_witness, wally_psbt_input_set_final_witness)
WALLY_FN_PP(psbt_input_set_keypaths, wally_psbt_input_set_keypaths)
WALLY_FN_PP(psbt_input_set_utxo, wally_psbt_input_set_utxo)
WALLY_FN_PP(psbt_input_set_signatures, wally_psbt_input_set_signatures)
WALLY_FN_PP(psbt_input_set_unknowns, wally_psbt_input_set_unknowns)
WALLY_FN_PP(psbt_input_set_witness_utxo, wally_psbt_input_set_witness_utxo)
WALLY_FN_PP(psbt_output_set_keypaths, wally_psbt_output_set_keypaths)
WALLY_FN_PP(psbt_output_set_unknowns, wally_psbt_output_set_unknowns)
WALLY_FN_PP(psbt_set_global_tx, wally_psbt_set_global_tx)
WALLY_FN_PP(tx_add_input, wally_tx_add_input)
WALLY_FN_PP(tx_add_output, wally_tx_add_output)
WALLY_FN_PP3_A(bip32_key_to_addr_segwit, wally_bip32_key_to_addr_segwit)
WALLY_FN_PP3_BS(addr_segwit_to_bytes, wally_addr_segwit_to_bytes)
WALLY_FN_PP_BS(bip39_mnemonic_to_bytes, bip39_mnemonic_to_bytes)
WALLY_FN_PP_BS(bip39_mnemonic_to_seed, bip39_mnemonic_to_seed)
WALLY_FN_PS(tx_remove_input, wally_tx_remove_input)
WALLY_FN_PS(tx_remove_output, wally_tx_remove_output)
WALLY_FN_PS3(tx_witness_stack_set_dummy, wally_tx_witness_stack_set_dummy)
WALLY_FN_PSB(tx_set_input_script, wally_tx_set_input_script)
WALLY_FN_PSB(tx_witness_stack_set, wally_tx_witness_stack_set)
WALLY_FN_PSB633_B(tx_get_btc_signature_hash, wally_tx_get_btc_signature_hash)
WALLY_FN_PSBB36333_B(tx_get_signature_hash, wally_tx_get_signature_hash)
WALLY_FN_PSP(tx_set_input_witness, wally_tx_set_input_witness)
WALLY_FN_PS_A(bip39_get_word, bip39_get_word)
WALLY_FN_P_A(bip32_key_from_base58_alloc, bip32_key_from_base58_alloc)
WALLY_FN_P_A(bip39_get_wordlist, bip39_get_wordlist)
WALLY_FN_P_A(psbt_extract, wally_psbt_extract)
WALLY_FN_P_A(psbt_from_base64, wally_psbt_from_base64)
WALLY_FN_P_A(tx_output_clone_alloc, wally_tx_output_clone_alloc)
WALLY_FN_P_A(tx_witness_stack_clone_alloc, wally_tx_witness_stack_clone_alloc)
WALLY_FN_P_B(bip32_key_get_fingerprint, bip32_key_get_fingerprint)
WALLY_FN_P_B(tx_get_txid, wally_tx_get_txid)
WALLY_FN_P_BS(hex_to_bytes, wally_hex_to_bytes)
WALLY_FN_P_P(bip32_key_from_base58, bip32_key_from_base58)
WALLY_FN_P_P(tx_get_total_output_satoshi, wally_tx_get_total_output_satoshi)
WALLY_FN_P_P(tx_output_clone, wally_tx_output_clone)
WALLY_FN_P_S(base58_get_length, wally_base58_get_length)
WALLY_FN_P_S(bip38_get_flags, bip38_get_flags)
WALLY_FN_P_S(psbt_input_is_finalized, wally_psbt_input_is_finalized)
WALLY_FN_P_S(psbt_is_elements, wally_psbt_is_elements)
WALLY_FN_P_S(psbt_is_finalized, wally_psbt_is_finalized)
WALLY_FN_P_S(tx_get_vsize, wally_tx_get_vsize)
WALLY_FN_P_S(tx_get_weight, wally_tx_get_weight)
WALLY_FN_P_S(tx_get_witness_count, wally_tx_get_witness_count)
WALLY_FN_P_S(tx_is_coinbase, wally_tx_is_coinbase)
WALLY_FN_P_S(wif_is_uncompressed, wally_wif_is_uncompressed)
WALLY_FN_S_A(tx_witness_stack_init_alloc, wally_tx_witness_stack_init_alloc)
WALLY_FN_S_A(map_init_alloc, wally_map_init_alloc)
WALLY_FN_S_S(tx_vsize_from_weight, wally_tx_vsize_from_weight)
WALLY_FN__A(bip39_get_languages, bip39_get_languages)

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
    size_t ret;
    ::wally_is_elements_build(&ret);
    return ret != 0;
}

#ifdef BUILD_ELEMENTS
WALLY_FN_3SSS_A(psbt_elements_init_alloc, wally_psbt_elements_init_alloc)
WALLY_FN_6BBBBBBBB6II_BS(asset_rangeproof, wally_asset_rangeproof)
WALLY_FN_6BB_B(asset_value_commitment, wally_asset_value_commitment)
WALLY_FN_6_B(tx_confidential_value_from_satoshi, wally_tx_confidential_value_from_satoshi)
WALLY_FN_B33BPBBBBBBP_A(tx_elements_input_init_alloc, wally_tx_elements_input_init_alloc)
WALLY_FN_B3B_B(tx_elements_issuance_generate_entropy, wally_tx_elements_issuance_generate_entropy)
WALLY_FN_B3_B(tx_elements_issuance_calculate_reissuance_token, wally_tx_elements_issuance_calculate_reissuance_token)
WALLY_FN_BB3_BS(elements_pegin_contract_script_from_bytes, wally_elements_pegin_contract_script_from_bytes)
WALLY_FN_BBBB3_BS(elements_pegout_script_from_bytes, wally_elements_pegout_script_from_bytes)
WALLY_FN_BBBBBBB_BS(asset_surjectionproof, wally_asset_surjectionproof)
WALLY_FN_BBBBBB_A(tx_elements_output_init_alloc, wally_tx_elements_output_init_alloc)
WALLY_FN_BBBBBB_P(tx_elements_output_init, wally_tx_elements_output_init)
WALLY_FN_BBBBBB_BBB6(asset_unblind, wally_asset_unblind)
WALLY_FN_BBBBB_BBB6(asset_unblind_with_nonce, wally_asset_unblind_with_nonce)
WALLY_FN_BBSBBB_BS(asset_pak_whitelistproof, wally_asset_pak_whitelistproof)
WALLY_FN_BB_B(asset_blinding_key_to_ec_private_key, wally_asset_blinding_key_to_ec_private_key)
WALLY_FN_BB_B(asset_generator_from_bytes, wally_asset_generator_from_bytes)
WALLY_FN_BSBB_B(asset_final_vbf, wally_asset_final_vbf)
WALLY_FN_B_6(tx_confidential_value_to_satoshi, wally_tx_confidential_value_to_satoshi)
WALLY_FN_B_B(asset_blinding_key_from_seed, wally_asset_blinding_key_from_seed)
WALLY_FN_B_B(tx_elements_issuance_calculate_asset, wally_tx_elements_issuance_calculate_asset)
WALLY_FN_P(psbt_input_clear_value, wally_psbt_input_clear_value)
WALLY_FN_P(psbt_finalize, wally_psbt_finalize)
WALLY_FN_P(tx_elements_input_issuance_free, wally_tx_elements_input_issuance_free)
WALLY_FN_P(tx_elements_output_commitment_free, wally_tx_elements_output_commitment_free)
WALLY_FN_P3B_A(confidential_addr_from_addr, wally_confidential_addr_from_addr)
WALLY_FN_P3_A(confidential_addr_to_addr, wally_confidential_addr_to_addr)
WALLY_FN_P3_B(confidential_addr_to_ec_public_key, wally_confidential_addr_to_ec_public_key)
WALLY_FN_P3B33BPBBBBBBP3(tx_add_elements_raw_input_at, wally_tx_add_elements_raw_input_at)
WALLY_FN_P3BBBBBB3(tx_add_elements_raw_output_at, wally_tx_add_elements_raw_output_at)
WALLY_FN_P6(psbt_input_set_value, wally_psbt_input_set_value)
WALLY_FN_PB(psbt_input_set_asset, wally_psbt_input_set_asset)
WALLY_FN_PB(psbt_input_set_abf, wally_psbt_input_set_abf)
WALLY_FN_PB(psbt_input_set_claim_script, wally_psbt_input_set_claim_script)
WALLY_FN_PB(psbt_input_set_genesis_blockhash, wally_psbt_input_set_genesis_blockhash)
WALLY_FN_PB(psbt_input_set_txoutproof, wally_psbt_input_set_txoutproof)
WALLY_FN_PB(psbt_input_set_vbf, wally_psbt_input_set_vbf)
WALLY_FN_PB(psbt_output_set_abf, wally_psbt_output_set_abf)
WALLY_FN_PB(psbt_output_set_asset_commitment, wally_psbt_output_set_asset_commitment)
WALLY_FN_PB(psbt_output_set_blinding_pubkey, wally_psbt_output_set_blinding_pubkey)
WALLY_FN_PB(psbt_output_set_nonce, wally_psbt_output_set_nonce)
WALLY_FN_PB(psbt_output_set_rangeproof, wally_psbt_output_set_rangeproof)
WALLY_FN_PB(psbt_output_set_surjectionproof, wally_psbt_output_set_surjectionproof)
WALLY_FN_PB(psbt_output_set_vbf, wally_psbt_output_set_vbf)
WALLY_FN_PB(psbt_output_set_value_commitment, wally_psbt_output_set_value_commitment)
WALLY_FN_PB33BPBBBBBBP3(tx_add_elements_raw_input, wally_tx_add_elements_raw_input)
WALLY_FN_PB3_P(bip32_key_with_tweak_from_parent_path, bip32_key_with_tweak_from_parent_path)
WALLY_FN_PB3_A(bip32_key_with_tweak_from_parent_path_alloc, bip32_key_with_tweak_from_parent_path_alloc)
WALLY_FN_PBBBBB(tx_elements_output_commitment_set, wally_tx_elements_output_commitment_set)
WALLY_FN_PBBBBBB(tx_elements_input_issuance_set, wally_tx_elements_input_issuance_set)
WALLY_FN_PBBBBBB3(tx_add_elements_raw_output, wally_tx_add_elements_raw_output)
WALLY_FN_PP(psbt_input_set_pegin_tx, wally_psbt_input_set_pegin_tx)
WALLY_FN_PPPB_A(confidential_addr_from_addr_segwit, wally_confidential_addr_from_addr_segwit)
WALLY_FN_PPP_A(confidential_addr_to_addr_segwit, wally_confidential_addr_to_addr_segwit)
WALLY_FN_PP_B(confidential_addr_segwit_to_ec_public_key, wally_confidential_addr_segwit_to_ec_public_key)
WALLY_FN_PSBB33_B(tx_get_elements_signature_hash, wally_tx_get_elements_signature_hash)
WALLY_FN_P_S(tx_elements_input_is_pegin, wally_tx_elements_input_is_pegin)
WALLY_FN_P_S(tx_is_elements, wally_tx_is_elements)
WALLY_FN_SSSS_S(elements_pegout_script_size, wally_elements_pegout_script_size)
WALLY_FN_S_S(asset_pak_whitelistproof_size, wally_asset_pak_whitelistproof_size)
WALLY_FN_S_S(asset_surjectionproof_size, wally_asset_surjectionproof_size)
#endif /* BUILD_ELEMENTS */

#undef WALLYP
#undef WALLYB
#undef WALLYO

} /* namespace wally */

#endif /* LIBWALLY_CORE_WALLY_HPP */
