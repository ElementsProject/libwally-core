/* Local copies of satisfaction lifecycle functions from descriptor.c.
 * These are internal to the library (hidden in the DSO) so the test
 * binary needs its own copy when compiling miniscript_satisfy.c. */
#include "config.h"
#include "descriptor_int.h"
#include <wally_core.h>
#include <string.h>

int ms_witness_init(ms_witness *w, uint32_t kind)
{
    memset(w, 0, sizeof(*w));
    w->kind = kind;
    return WALLY_OK;
}

void ms_witness_free(ms_witness *w)
{
    if (w) {
        size_t i;
        for (i = 0; i < w->num_items; i++)
            wally_free(w->items[i].data);
        wally_free(w->items);
        memset(w, 0, sizeof(*w));
    }
}

int ms_satisfaction_init(ms_satisfaction *s, uint32_t witness_kind)
{
    int ret = ms_witness_init(&s->witness, witness_kind);
    s->has_sig = false;
    s->absolute_timelock = 0;
    s->relative_timelock = 0;
    return ret;
}

void ms_satisfaction_free(ms_satisfaction *s)
{
    if (s) {
        ms_witness_free(&s->witness);
        memset(s, 0, sizeof(*s));
    }
}
