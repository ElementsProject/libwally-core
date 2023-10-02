#ifndef LIBWALLY_CORE_COINSELECTION_H
#define LIBWALLY_CORE_COINSELECTION_H

#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The maximum number of asset values that can be returned in a coin selection */
#define WALLY_CS_MAX_ASSETS 256

#ifndef WALLY_ABI_NO_ELEMENTS

/**
 * Select input asset values to meet a given payment target.
 *
 * :param values: The UTXO asset values to select from. Must be ordered from
 *|    largest to smallest.
 * :param num_values: The number of asset values in ``values``.
 * :param target: The desired payment value target.
 * :param attempts: The maximum number of permutations to check. Must be at
 *|    least ``num_values`` + 1.
 * :param io_ratio: The approximate expected ratio of input to output sizes
 *|    in the resulting transaction. Larger values will result in more
 *|    input permutations being searched for exact matches. Must be non-zero,
 *|    a good default value is ``5``.
 * :param indices_out: Destination for the zero-based indices into ``values``
 *|    making up the chosen solution. Must be at least the smaller
 *|    of ``num_values`` and `WALLY_CS_MAX_ASSETS`.
 * MAX_SIZED_OUTPUT(indices_out_len, indices_out, WALLY_CS_MAX_ASSETS)
 * :param written: Destination for the the number of indices written
 *|    to ``indices_out``.
 *
 * This function always finds a solution if one is available. If the given
 * values are insufficient to reach the target then zero elements will be
 * returned. If the sum of the values returned is not equal to ``target``
 * then a change output for the remainder will be required.
 */
WALLY_CORE_API int wally_coinselect_assets(
    const uint64_t *values,
    size_t num_values,
    uint64_t target,
    uint64_t attempts,
    uint32_t io_ratio,
    uint32_t *indices_out,
    size_t indices_out_len,
    size_t *written);

#endif /* WALLY_ABI_NO_ELEMENTS */

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_COINSELECTION_H */
