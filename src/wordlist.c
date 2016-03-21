#include "wordlist.h"
#include <string.h>

static int bstrcmp(const void *l, const void *r)
{
    return strcmp(l, (*(const char **)r));
}

/* https://graphics.stanford.edu/~seander/bithacks.html#IntegerLogObvious */
inline static int get_bits(size_t n)
{
    size_t bits = 0;
    while (n >>= 1)
        ++bits;
    return bits;
}

/* Allocate a new words structure */
static struct words *wordlist_alloc(const char *words, size_t len)
{
    struct words *w = malloc(sizeof(struct words));
    if (w) {
        w->str = strdup(words);
        if (w->str) {
            w->len = len;
            w->bits = get_bits(len);
            w->indices = malloc(len * sizeof(const char *));
            if (w->indices)
                return w;
            free((void *)w->str);
        }
        free(w);
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
    struct words *w = 0;
    size_t i, len = wordlist_count(words);

    if ((w = wordlist_alloc(words, len))) {
        /* Tokenise the strings into w->indices */
        const char *p = w->str;
        for (len = 0; len < w->len; ++len) {
            w->indices[len] = p;
            while (*p && *p != ' ') /* FIXME: utf-8 sep */
                ++p;
            *((char *)p) = '\0';
            ++p;
        }
    }

    w->sorted = true;
    for (i = 1; i < len && w->sorted; ++i)
        if (strcmp(w->indices[i - 1], w->indices[i]) > 0)
            w->sorted = false;

    return w;
}

size_t wordlist_lookup_word(const struct words *w, const char *word)
{
    const size_t size = sizeof(const char *);
    const char **found = NULL;

    if (w->sorted)
        found = (const char **)bsearch(word, w->indices, w->len, size, bstrcmp);
    else {
        size_t i;
        for (i = 0; i < w->len && !found; ++i)
            if (!strcmp(word, w->indices[i]))
                found = w->indices + i;
    }
    return found ? found - w->indices + 1u : 0u;
}

const char *wordlist_lookup_index(const struct words *w, size_t index)
{
    if (index >= w->len)
        return NULL;
    return w->indices[index];
}

void wordlist_free(struct words *w)
{
    free((void *)w->str);
    free((void *)w->indices);
    free(w);
}
