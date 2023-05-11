#include "internal.h"

#include <include/wally_coinselection.h>

typedef struct value_remaining {
    uint64_t remaining;
    uint64_t value;
} value_remaining_t;

/*
 * Coin selection for assets is much simpler than the policy asset L-BTC.
 *
 * Assumptions/Limits:
 * - We can only have up to 252 + 1 change asset outputs, allowing 1 fee and
 *   1 L-BTC change output to remain within the Elements 255 output limit.
 * - We limit the number of asset inputs in the solution to 256 for simplicity.
 *   Finding such a solution other than a trivial one in computationally
 *   feasible time is highly improbable anyway.
 * - We assume the outputs will be blinded.
 * - The same asset is usually/mostly received to the same wallet/on the same
 *   address type and so we can ignore effective value in favour of absolute
 *   value.
 * - Dust is not meaningful for assets, since we cannot know their value
 *   relative to L-BTC. We nevertheless attempt to use only the largest UTXOs.
 * - Privacy is somewhat protected by blinding of the asset and value, so we
 *   do not care about spending the same addresses together.
 * - For the same reason we do not need to randomize which UTXOs we search,
 *   since the algorithm used (and thus potentially the wallet) cannot be
 *   inferred from the size + ordering of the inputs.
 * - For the same reason we do not need to attempt to make change outputs the
 *   same size as the payment output(s).
 * - Fees and long term fees are both low; we do not expect created outputs to
 *   be significantly more expensive to spend in the future vs now.
 * - Blinded outputs are significantly more expensive than inputs due to
 *   the range and surjection proofs. Finding larger inputs sets that avoid a
 *   change output is thus worthwhile if feasible. This is expressed by
 *   io_ratio which is the number of extra inputs we allow to avoid a
 *   change output.
 * - Blocks are fast, regular and rarely full; we don't need to be concerned
 *   with spending unconfirmed inputs.
 * - Ensuring we can RBF by including a change output is not relevant since
 *   fees are paid in L-BTC and it is the L-BTC change output that matters for
 *   RBF.
 *
 * We iterate possible solution permutations up to an attempt limit, keeping
 * the best match found using the following criteria:
 * - Exact matches are preferred to change-generating matches when they use
 *   up to io_ratio more inputs.
 * - All else being equal, prefer fewer inputs.
 * - All else being equal, prefer larger change.
 *
 * The caller can opt to prefer UTXO consolidation/avoid change by increasing
 * the io_ratio passed in, which increases the search space and prefers to
 * use more inputs if a changeless solution is found.
 *
 * We implement the core optimisations:
 * - Cut the search branch when it cannot reach the target
 * - Cut the search branch when it exceeds the target (after scoring it)
 * - Do not test equivalent combinations
 *
 * We add two additional optimisations. First, we return immediately if we find
 * a single input exact match, since that represents the best match possible.
 * Second, we cut the search branch when the number of selected inputs
 * is enough that even an exact match would not score better than the current
 * match. Since we search depth first from from the largest values to the
 * smallest, once N inputs have been found that reach the target, only
 * permutations containing up to N+io_ratio inputs will be considered
 * from that point on, which massively reduces the search space for large
 * UTXO sets.
 *
 * One nice property of the search is that we will always find a solution if
 * one exists with at most num_inputs + 1 attempts (i.e. if all inputs are
 * required to reach the target), however suboptimal that solution may be.
 * We thus require num_inputs + 1 attempts be passed in, so that a returned
 * empty result set means that no other algorithm would find a solution.
 *
 * The long term behaviour on a set of UTXOs is expected to be that large
 * UTXOs will be shrunk to more-or-less the average payment size, with
 * consolidation occurring when change can be avoided or as multiple inputs
 * are required to reach the payment target.
 */
int wally_coinselect_assets(const uint64_t *values, size_t num_values,
                            uint64_t target, uint64_t attempts, uint32_t io_ratio,
                            uint32_t *indices_out, size_t indices_out_len,
                            size_t *written)
{
    uint64_t remaining, sum = 0, best_sum = 0;
    uint32_t best_score = 0xffffffff, v = 0, ii = 0;
    size_t i, attempt;
    value_remaining_t *vr;
    uint32_t indices[WALLY_CS_MAX_ASSETS];

    if (written)
        *written = 0;
    if (!values || !num_values || !target ||
        attempts < num_values + 1 || !io_ratio || !indices_out ||
        (indices_out_len < num_values && indices_out_len < WALLY_CS_MAX_ASSETS) ||
        !written)
        return WALLY_EINVAL;

    /* Compute the remaining sum of all values from a given index */
    for (i = 0, remaining = 0; i < num_values; ++i)
        remaining += values[i];
    if (remaining < target)
        return WALLY_OK; /* Insufficient total funds to hit target */

    vr = wally_malloc((num_values + 1) * sizeof(value_remaining_t));
    if (!vr)
        return WALLY_ENOMEM;

    for (i = 0; i < num_values; ++i) {
        vr[i].remaining = remaining;
        vr[i].value = values[i];
        remaining -= values[i];
    }
    vr[i].remaining = 0;
    vr[i].value = 0;

    for (attempt = 0; attempt < attempts; ++attempt) {
        bool backtrack = false;

        if (sum + vr[v].remaining < target) {
            /* Current selection plus remaining amount can not reach target */
            backtrack = true;
        } else if (sum >= target) {
            /* Current selection reaches or exceeds the target */
            const uint64_t score = ii + (sum == target ? 0 : io_ratio);

            if (score < best_score ||
                (score == best_score &&
                (sum > best_sum || (sum == target && best_sum != target)))) {
                /* This selection is 'better' by our criteria, use it */
                best_score = score;
                best_sum = sum;
                *written = ii;
                for (i = 0; i < ii; ++i)
                    indices_out[i] = indices[i];
                if (sum == target && ii == 1)
                    break; /* Perfect selection: don't try for better */
            }
            backtrack = true;
        } else if (ii >= best_score || ii >= WALLY_CS_MAX_ASSETS) {
            /* We cannot beat the best score by adding more inputs */
            backtrack = true;
        }

        if (backtrack) {
            if (ii-- == 0)
                break; /* All viable selections have been searched */

            while (--v > indices[ii])
                /* Loop adding omitted UTXO values to the available selection */;

            sum -= vr[v].value; /* Remove last included UTXO value from the selection */
        } else if (ii == 0 ||                        /* First UTXO value, or */
                   v - 1 == indices[ii - 1] ||       /* Previous index is included, or */
                   vr[v].value != vr[v - 1].value) { /* UTXO value is different */
            /* Add this UTXOs value to the selection */
            indices[ii++] = v;
            sum += vr[v].value;
        }

        ++v;
    }
    wally_free(vr);
    return WALLY_OK;
}
