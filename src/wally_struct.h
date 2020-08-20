#ifndef LIBWALLY_CORE_WALLY_STRUCT_H
#define LIBWALLY_CORE_WALLY_STRUCT_H 1

/* Helpers to implemented getters and setters for struct members.
 *
 * For our wrapped languages we need getter/setter functions since they
 * can't directly read through the opaque pointers holding structs.
 * For nested values we have to support indexed getters/setters too.
 *
 * These macros make the declaration and definition of such functions
 * a little cleaner.
 *
 * STRUCT - A struct set and fetched by value with a clone function
 * VARBUF - A pointer and length.
 * INT    - An integer type.
 * OPTINT - An optional integer type.
 * MAP    - A wally_map.
 *
 * XXX_DECL - Declares functions in a given scope, suitable for SWIG parsing.
 * XXX_IMPL - Implements the functions in a given scope.
 */

/*
 * Members nested in an array in a struct
 */

#define NESTED_STRUCT_DECL(SCOPE, PARENT, COLLECTION, STRUCT_TYPE, NAME) \
    SCOPE int PARENT ## _set_ ## COLLECTION ## _ ## NAME(struct PARENT *p, size_t i, const struct STRUCT_TYPE *ps); \
    SCOPE int PARENT ## _get_ ## COLLECTION ## _ ## NAME ## _alloc(const struct PARENT *p, size_t i, struct STRUCT_TYPE **output)

#define NESTED_STRUCT_IMPL(SCOPE, PARENT, COLLECTION, STRUCT_TYPE, NAME, CLONE_FN, USE_SETTER) \
    SCOPE int PARENT ## _set_ ## COLLECTION ## _ ## NAME(struct PARENT *p, size_t i, const struct STRUCT_TYPE *ps) { \
        if (!p || i >= p->num_ ## COLLECTION ## s) return WALLY_EINVAL; \
        if (USE_SETTER) return PARENT ## _ ## COLLECTION ## _set_ ## NAME(&p->COLLECTION ## s[i], ps); \
        else { \
            struct STRUCT_TYPE *new_ps = NULL; \
            int ret = ps ? CLONE_FN(ps, &new_ps) : WALLY_OK; \
            if (ret == WALLY_OK) { STRUCT_TYPE ## _free(p->COLLECTION ## s[i].NAME); p->COLLECTION ## s[i].NAME = new_ps; } \
            return ret; \
        } \
    } \
    SCOPE int PARENT ## _get_ ## COLLECTION ## _ ## NAME ## _alloc(const struct PARENT *p, size_t i, struct STRUCT_TYPE **output) { \
        if (output) *output = NULL; \
        if (!p || !output || i >= p->num_ ## COLLECTION ## s) return WALLY_EINVAL; \
        return CLONE_FN(p->COLLECTION ## s[i].NAME, output); \
    }


#define NESTED_VARBUF_DECL(SCOPE, PARENT, COLLECTION, NAME) \
    SCOPE int PARENT ## _set_ ## COLLECTION ## _ ## NAME(struct PARENT *p, size_t i, const unsigned char *bytes, size_t bytes_len); \
    SCOPE int PARENT ## _get_ ## COLLECTION ## _ ## NAME(const struct PARENT *p, size_t i, unsigned char *bytes_out, size_t len, size_t *written); \
    SCOPE int PARENT ## _get_ ## COLLECTION ## _ ## NAME ## _len(const struct PARENT *p, size_t i, size_t *written)

#define NESTED_VARBUF_IMPL(SCOPE, PARENT, COLLECTION, NAME, USE_SETTER) \
    SCOPE int PARENT ## _set_ ## COLLECTION ## _ ## NAME(struct PARENT *p, size_t i, const unsigned char *bytes, size_t bytes_len) { \
        if (!p || i >= p->num_ ## COLLECTION ## s) return WALLY_EINVAL; \
        if (USE_SETTER) return PARENT ## _ ## COLLECTION ## _set_ ## NAME(&p->COLLECTION ## s[i], bytes, bytes_len); \
        return replace_bytes(bytes, bytes_len, &p->COLLECTION ## s[i].NAME, &p->COLLECTION ## s[i].NAME ## _len); \
    } \
    SCOPE int PARENT ## _get_ ## COLLECTION ## _ ## NAME(const struct PARENT *p, size_t i, unsigned char *bytes_out, size_t len, size_t *written) { \
        if (written) *written = 0; \
        if (!p || !bytes_out || !len || !written || i >= p->num_ ## COLLECTION ## s) return WALLY_EINVAL; \
        *written = p->COLLECTION ## s[i].NAME ## _len; \
        if (*written && len >= *written) memcpy(bytes_out, p->COLLECTION ## s[i].NAME, *written); \
        return WALLY_OK; \
    } \
    SCOPE int PARENT ## _get_ ## COLLECTION ## _ ## NAME ## _len(const struct PARENT *p, size_t i, size_t *written) { \
        if (written) *written = 0; \
        if (!p || !written || i >= p->num_ ## COLLECTION ## s) return WALLY_EINVAL; \
        *written = p->COLLECTION ## s[i].NAME ## _len; \
        return WALLY_OK; \
    }


#define NESTED_INT____DECL(SCOPE, PARENT, COLLECTION, INT_TYPE, NAME) \
    SCOPE int PARENT ## _set_ ## COLLECTION ## _ ## NAME(struct PARENT *p, size_t i, INT_TYPE value); \
    SCOPE int PARENT ## _get_ ## COLLECTION ## _ ## NAME(const struct PARENT *p, size_t i, INT_TYPE *value_out)

#define NESTED_INT____IMPL(SCOPE, PARENT, COLLECTION, INT_TYPE, NAME, USE_SETTER) \
    SCOPE int PARENT ## _set_ ## COLLECTION ## _ ## NAME(struct PARENT *p, size_t i, INT_TYPE value) { \
        if (!p || i >= p->num_ ## COLLECTION ## s) return WALLY_EINVAL; \
        if (USE_SETTER) return PARENT ## _ ## COLLECTION ## _set_ ## NAME(&p->COLLECTION ## s[i], value); \
        p->COLLECTION ## s[i].NAME = value; \
        return WALLY_OK; \
    } \
    SCOPE int PARENT ## _get_ ## COLLECTION ## _ ## NAME(const struct PARENT *p, size_t i, INT_TYPE *value_out) { \
        if (!p || !value_out || i >= p->num_ ## COLLECTION ## s) return WALLY_EINVAL; \
        *value_out = p->COLLECTION ## s[i].NAME; \
        return WALLY_OK; \
    }


#define NESTED_OPTINT_DECL(SCOPE, PARENT, COLLECTION, INT_TYPE, NAME) \
    SCOPE int PARENT ## _set_ ## COLLECTION ## _ ## NAME(struct PARENT *p, size_t i, INT_TYPE value); \
    SCOPE int PARENT ## _get_ ## COLLECTION ## _ ## NAME(const struct PARENT *p, size_t i, INT_TYPE *value_out); \
    SCOPE int PARENT ## _clear_ ## COLLECTION ## _ ## NAME(struct PARENT *p, size_t i); \
    SCOPE int PARENT ## _has_ ## COLLECTION ## _ ## NAME(const struct PARENT *p, size_t i, size_t *written)

#define NESTED_OPTINT_IMPL(SCOPE, PARENT, COLLECTION, INT_TYPE, NAME, USE_SETTER) \
    SCOPE int PARENT ## _set_ ## COLLECTION ## _ ## NAME(struct PARENT *p, size_t i, INT_TYPE value) { \
        if (!p || i >= p->num_ ## COLLECTION ## s) return WALLY_EINVAL; \
        if (USE_SETTER) return PARENT ## _ ## COLLECTION ## _set_ ## NAME(&p->COLLECTION ## s[i], value); \
        p->COLLECTION ## s[i].NAME = value; p->COLLECTION ## s[i].has_ ## NAME = 1u; \
        return WALLY_OK; \
    } \
    SCOPE int PARENT ## _get_ ## COLLECTION ## _ ## NAME(const struct PARENT *p, size_t i, INT_TYPE *value_out) { \
        if (!p || !value_out || i >= p->num_ ## COLLECTION ## s || !p->COLLECTION ## s[i].has_ ## NAME) return WALLY_EINVAL; \
        *value_out = p->COLLECTION ## s[i].NAME; \
        return WALLY_OK; \
    } \
    SCOPE int PARENT ## _clear_ ## COLLECTION ## _ ## NAME(struct PARENT *p, size_t i) { \
        if (!p || i >= p->num_ ## COLLECTION ## s) return WALLY_EINVAL; \
        p->COLLECTION ## s[i].NAME = 0; p->COLLECTION ## s[i].has_ ## NAME = 0; \
        return WALLY_OK; \
    } \
    SCOPE int PARENT ## _has_ ## COLLECTION ## _ ## NAME(const struct PARENT *p, size_t i, size_t *written) { \
        if (written) *written = 0; \
        if (!p || !written || i >= p->num_ ## COLLECTION ## s) return WALLY_EINVAL; \
        *written = p->COLLECTION ## s[i].has_ ## NAME ? 1u : 0; \
        return WALLY_OK; \
    }


#define NESTED_MAP____DECL(SCOPE, PARENT, COLLECTION, NAME) \
    SCOPE int PARENT ## _set_ ## COLLECTION ## _ ## NAME ## s(struct PARENT *p, size_t i, const struct wally_map *map_in); \
    SCOPE int PARENT ## _get_ ## COLLECTION ## _ ## NAME ## s_size(const struct PARENT *p, size_t i, size_t *written); \
    SCOPE int PARENT ## _find_ ## COLLECTION ## _ ## NAME(const struct PARENT *p, size_t i, const unsigned char *bytes, size_t bytes_len, size_t *written); \
    SCOPE int PARENT ## _get_ ## COLLECTION ## _ ## NAME(const struct PARENT *p, size_t i, size_t sub_i, unsigned char *bytes_out, size_t len, size_t *written); \
    SCOPE int PARENT ## _get_ ## COLLECTION ## _ ## NAME ## _len(const struct PARENT *p, size_t i, size_t sub_i, size_t *written)

#define NESTED_MAP____IMPL(SCOPE, PARENT, COLLECTION, NAME, CHECK_FN, USE_SETTER) \
    SCOPE int PARENT ## _set_ ## COLLECTION ## _ ## NAME ## s(struct PARENT *p, size_t i, const struct wally_map *map_in) { \
        if (!p || i >= p->num_ ## COLLECTION ## s) return WALLY_EINVAL; \
        if (USE_SETTER) return PARENT ## _ ## COLLECTION ## _set_ ## NAME ## s(&p->COLLECTION ## s[i], map_in); \
        return map_assign(map_in, &p->COLLECTION ## s[i].NAME ## s, CHECK_FN); \
    } \
    SCOPE int PARENT ## _get_ ## COLLECTION ## _ ## NAME ## s_size(const struct PARENT *p, size_t i, size_t *written) { \
        if (written) *written = 0; \
        if (!p || !written || i >= p->num_ ## COLLECTION ## s) return WALLY_EINVAL; \
        *written = p->COLLECTION ## s[i].NAME ## s.num_items; \
        return WALLY_OK; \
    } \
    SCOPE int PARENT ## _find_ ## COLLECTION ## _ ## NAME(const struct PARENT *p, size_t i, const unsigned char *bytes, size_t bytes_len, size_t *written) { \
        if (written) *written = 0; \
        if (!p || i >= p->num_ ## COLLECTION ## s) return WALLY_EINVAL; \
        return wally_map_find(&p->COLLECTION ## s[i].NAME ## s, bytes, bytes_len, written); \
    } \
    SCOPE int PARENT ## _get_ ## COLLECTION ## _ ## NAME(const struct PARENT *p, size_t i, size_t sub_i, unsigned char *bytes_out, size_t len, size_t *written) { \
        if (written) *written = 0; \
        if (!p || !written || i >= p->num_ ## COLLECTION ## s || !bytes_out || !len || \
            sub_i >= p->COLLECTION ## s[i].NAME ## s.num_items) \
            return WALLY_EINVAL; \
        *written = p->COLLECTION ## s[i].NAME ## s.items[sub_i].value_len; \
        if (*written && len >= *written) memcpy(bytes_out, p->COLLECTION ## s[i].NAME ## s.items[sub_i].value, *written); \
        return WALLY_OK; \
    } \
    SCOPE int PARENT ## _get_ ## COLLECTION ## _ ## NAME ## _len(const struct PARENT *p, size_t i, size_t sub_i, size_t *written) { \
        if (written) *written = 0; \
        if (!p || !written || i >= p->num_ ## COLLECTION ## s || sub_i >= p->COLLECTION ## s[i].NAME ## s.num_items) return WALLY_EINVAL; \
        *written = p->COLLECTION ## s[i].NAME ## s.items[sub_i].value_len; \
        return WALLY_OK; \
    }

#endif /* LIBWALLY_CORE_WALLY_STRUCT_H */
