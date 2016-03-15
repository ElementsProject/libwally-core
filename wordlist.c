#include "wordlist.h"
#include <string.h>

static int bstrcmp(const void *l, const void *r)
{
   return strcmp(l, (*(const char**)r));
}

/* https://graphics.stanford.edu/~seander/bithacks.html#DetermineIfPowerOf2 */
inline static int is_power_of_two(size_t n)
{
    /* Minimum size is two words giving one bit numbers */
    return n >= 2 && !(n & (n - 1));
}

/* Allocate a new words structure */
static struct words *wordlist_alloc(const char* words, size_t len)
{
    struct words *w = malloc(sizeof(struct words));
    if (w) {
        w->str = strdup(words);
        if (w->str) {
            w->len = len;
            w->indices = malloc(len * sizeof(const char*));
            if (w->indices)
                return w;
            free((void *)w->str);
        }
        free(w);
    }
    return NULL;
}

struct words *wordlist_init(const char *words, char sep)
{
    struct words *w = 0;
    const char *p = words;
    size_t len = 1u; /* Always 1 less separator than words, so start from 1 */

    while (*p)
        len += *p++ == sep;

    if (is_power_of_two(len) && (w = wordlist_alloc(words, len))) {
       /* Tokenise the strings into w->indices */
        for (len = 0, p = w->str; len < w->len; ++len) {
            w->indices[len] = p;
            while (*p && *p != sep)
                ++p;
            *((char *)p) = '\0';
            ++p;
        }
    }

    return w;
}

size_t wordlist_lookup_word(const struct words *w, const char *word)
{
    const size_t size = sizeof(const char*);
    const char **found;

    found = (const char **)bsearch(word, w->indices, w->len, size, bstrcmp);

    return found ? found - w->indices + 1u : 0u;
}

const char* wordlist_lookup_index(const struct words *w, size_t index)
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
