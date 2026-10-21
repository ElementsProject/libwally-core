#include "internal.h"
#include "wordlist.h"

/* The maximum offset that can be stored in a wordlist index */
#define WORDLIST_INDEX_MAX 0xffffu

static inline const char *wordlist_at(const struct words *w, size_t idx)
{
    return w->str + w->indices[idx];
}

static bool wordlist_bsearch(const struct words *w, const char *word, size_t *index_out)
{
    size_t lo = 0, hi = w->len;

    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2u;
        const int cmp = strcmp(word, wordlist_at(w, mid));
        if (!cmp) {
            *index_out = mid;
            return true;
        }
        if (cmp < 0)
            hi = mid;
        else
            lo = mid + 1;
    }
    return false;
}

/* https://graphics.stanford.edu/~seander/bithacks.html#IntegerLogObvious */
static size_t get_bits(size_t n)
{
    size_t bits = 0;
    while (n >>= 1)
        ++bits;
    return bits;
}

/* Allocate a new words structure */
static struct words *wordlist_alloc(const char *words, size_t len)
{
    struct words *w = wally_malloc(sizeof(struct words));
    if (w) {
        wally_clear(w, sizeof(*w));
        w->str = wally_strdup(words);
        if (w->str) {
            w->str_len = strlen(w->str);
            if (w->str_len <= 0xffff) {
                /* Word offsets fits into unsigned shorts */
                w->len = len;
                w->bits = get_bits(len);
                w->indices = wally_malloc(len * sizeof(*w->indices));
                if (w->indices)
                    return w;
            }
        }
        wordlist_free(w);
    }
    return NULL;
}

static size_t wordlist_count(const char *words)
{
    size_t len = 1u; /* Always 1 less separator than words, so start from 1 */
    while (*words)
        len += *words++ == ' '; /* FIXME: utf-8 sep */
    return len;
}

struct words *wordlist_init(const char *words)
{
    size_t i, len = wordlist_count(words);
    struct words *w = wordlist_alloc(words, len);

    if (w) {
        /* Tokenise the strings, storing their offsets into w->indices */
        unsigned short *indices = (unsigned short *) w->indices;
        const char *p = w->str;
        for (len = 0; len < w->len; ++len) {
            indices[len] = (unsigned short)(p - w->str);
            while (*p && *p != ' ') /* FIXME: utf-8 sep */
                ++p;
            *((char *)p) = '\0';
            ++p;
        }

        w->sorted = true;
        for (i = 1; i < len && w->sorted; ++i)
            if (strcmp(wordlist_at(w, i - 1), wordlist_at(w, i)) > 0)
                w->sorted = false;
    }
    return w;
}

size_t wordlist_lookup_word(const struct words *w, const char *word)
{
    size_t i;

    if (w->sorted) {
        if (!wordlist_bsearch(w, word, &i))
            return 0;
        return i + 1u;
    }
    for (i = 0; i < w->len; ++i)
        if (!strcmp(word, wordlist_at(w, i)))
            return i + 1u;
    return 0;
}

const char *wordlist_lookup_index(const struct words *w, size_t idx)
{
    if (idx >= w->len)
        return NULL;
    return wordlist_at(w, idx);
}

void wordlist_free(struct words *w)
{
    if (w) {
        if (w->str) {
            if (w->str_len)
                wally_clear((void *)w->str,  w->str_len);
            wally_free((void *)w->str);
        }
        if (w->indices)
            wally_free((void *)w->indices); /* No need to clear */
        clear_and_free(w, sizeof(*w));
    }
}
