#ifndef LIBWALLY_WORDLIST_H
#define LIBWALLY_WORDLIST_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

/**
 * struct words- structure representing a parsed list of words
 */
struct words {
    /* Number of words in the list */
    size_t len;
    /* Number of bits representable by this word list */
    size_t bits;
    /* Is the word list sorted by unicode code point order? */
    bool sorted;
    /* The underlying string (tokenised, containing embedded NULs) */
    const char *str;
    /* The length of str, or 0 if str points to constant storage */
    size_t str_len;
    /* Pointers to the individual words */
    const char **indices;
};

/**
 * wordlist_init - Initialise a words structure.
 * @text: List of words to initialise from, split by whitespace and
 *        NUL terminated. Must be UTF-8 encoded.
 *
 * The returned structure contains a copy of @text.
 */
struct words *wordlist_init(const char *text);

/**
 * wordlist_lookup_word - Find a word in a wordlist.
 * @w: Parsed list of words to look up in.
 * @word: The word to look up.
 *
 * Returns 0 if not found, index + 1 otherwise.
 * @see wordlist_init.
 */
size_t wordlist_lookup_word(const struct words *w, const char *word);

/**
 * wordlist_lookup_index - Return the Nth word in a wordlist.
 * @w: Parsed list of words to look up in.
 * @index: The index to look up.
 *
 * Returns NULL if not found, the word otherwise.
 */
const char *wordlist_lookup_index(const struct words *w, size_t index);

/**
 * wordlist_free - Free a words structure.
 * @w: structure to free.
 */
void wordlist_free(struct words *w);

#endif /* LIBWALLY_WORDLIST_H */
