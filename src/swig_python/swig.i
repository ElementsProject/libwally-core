%module wallycore
%{
#define SWIG_FILE_WITH_INIT
#include <stdbool.h>
#include "../include/wally_core.h"
#include "../include/wally_bip32.h"
#include "bip32_int.h"
#include "../include/wally_bip38.h"
#include "../include/wally_bip39.h"
#include "../include/wally_crypto.h"
#include "../internal.h"

#undef malloc
#undef free
#define malloc(size) wally_malloc(size)
#define free(ptr) wally_free(ptr)

static int check_result(int result)
{
    switch (result) {
    case WALLY_OK:
        break;
    case WALLY_EINVAL:
        PyErr_SetString(PyExc_ValueError, "Invalid argument");
        break;
    case WALLY_ENOMEM:
        PyErr_SetString(PyExc_MemoryError, "Out of memory");
        break;
    default: /* WALLY_ERROR */
         PyErr_SetString(PyExc_RuntimeError, "Failed");
         break;
    }
    return result;
}

#define capsule_cast(obj, name) \
    (struct name *)PyCapsule_GetPointer(obj, "struct " #name " *")

static void destroy_words(PyObject *obj) { (void)obj; }
static void destroy_ext_key(PyObject *obj) {
    struct ext_key *contained = capsule_cast(obj, ext_key);
    if (contained)
        bip32_key_free(contained);
}

#define MAX_LOCAL_STACK 256u
%}

%include pybuffer.i
%include exception.i

/* Raise an exception whenever a function fails */
%exception{
    $action
    if (check_result(result))
        SWIG_fail;
};

/* Return None if we didn't throw instead of 0 */
%typemap(out) int %{
    Py_IncRef(Py_None);
    $result = Py_None;
%}

%define %pybuffer_nullable_binary(TYPEMAP, SIZE)
%typemap(in) (TYPEMAP, SIZE)
  (int res, Py_ssize_t size = 0, const void *buf = 0) {
  if ($input == Py_None)
    $2 = 0;
  else {
    res = PyObject_AsReadBuffer($input, &buf, &size);
    if (res<0) {
      PyErr_Clear();
      %argument_fail(res, "(TYPEMAP, SIZE)", $symname, $argnum);
    }
    $1 = ($1_ltype) buf;
    $2 = ($2_ltype) (size / sizeof($*1_type));
  }
}
%enddef

/* Input buffers with lengths are passed as python buffers */
%pybuffer_nullable_binary(const unsigned char *bytes_in, size_t len_in);
%pybuffer_binary(const unsigned char *chain_code, size_t chain_code_len);
%pybuffer_nullable_binary(const unsigned char *hash160, size_t hash160_len);
%pybuffer_binary(const unsigned char *iv, size_t iv_len);
%pybuffer_binary(const unsigned char *key, size_t key_len);
%pybuffer_binary(const unsigned char *pass, size_t pass_len);
%pybuffer_nullable_binary(const unsigned char *parent160, size_t parent160_len);
%pybuffer_nullable_binary(const unsigned char *priv_key, size_t priv_key_len);
%pybuffer_nullable_binary(const unsigned char *pub_key, size_t pub_key_len);
%pybuffer_binary(const unsigned char *salt, size_t salt_len);
%pybuffer_binary(const unsigned char *sig_in, size_t sig_in_len);
%pybuffer_mutable_binary(unsigned char *bytes_out, size_t len);
%pybuffer_mutable_binary(unsigned char *bytes_in_out, size_t len);
%pybuffer_mutable_binary(unsigned char *salt_in_out, size_t salt_len);

/* Output parameters indicating how many bytes were written are converted
 * into return values. */
%typemap(in, numinputs=0) size_t *written (size_t sz) {
   sz = 0; $1 = ($1_ltype)&sz;
}
%typemap(argout) size_t* {
   Py_DecRef($result);
   $result = PyInt_FromSize_t(*$1);
}

/* Output strings are converted to native python strings and returned */
%typemap(in, numinputs=0) char** (char* txt) {
   txt = NULL;
   $1 = ($1_ltype)&txt;
}
%typemap(argout) char** {
   if (*$1 != NULL) {
       Py_DecRef($result);
       $result = PyString_FromString(*$1);
       wally_free_string(*$1);
   }
}

/* Opaque types are passed along as capsules */
%define %py_opaque_struct(NAME)
%typemap(in, numinputs=0) const struct NAME **output (struct NAME * w) {
   w = 0; $1 = ($1_ltype)&w;
}
%typemap(argout) const struct NAME ** {
   if (*$1 != NULL) {
       Py_DecRef($result);
       $result = PyCapsule_New(*$1, "struct NAME *", destroy_ ## NAME);
   }
}
%typemap (in) const struct NAME * {
    $1 = PyCapsule_GetPointer($input, "struct NAME *");
}
%enddef

/* uint32_t arrays FIXME: Generalise to other data types if needed */
%typemap(in) (uint32_t *STRING, size_t LENGTH) (uint32_t tmp_buf[MAX_LOCAL_STACK/sizeof(uint32_t)]) {
   size_t i;
   if (!PyList_Check($input)) {
       check_result(WALLY_EINVAL);
       SWIG_fail;
   }
   $2 = PyList_Size($input);
   $1 = tmp_buf;
   if ($2 * sizeof(uint32_t) > sizeof(tmp_buf))
       if (!($1 = (uint32_t *) wally_malloc(($2) * sizeof(uint32_t)))) {
           check_result(WALLY_ENOMEM);
           SWIG_fail;
       }
   for (i = 0; i < $2; ++i) {
       PyObject *item = PyList_GET_ITEM($input, i);
       Py_ssize_t value = PyNumber_AsSsize_t(item, NULL);
       if (value >= 0 && value <= 0xffffffff) {
           $1[i] = (uint32_t)value;
           continue;
       }
       PyErr_SetString(PyExc_OverflowError, "List item cannot be represented as uint32_t");
       SWIG_fail;
   }
}
%typemap(freearg) (uint32_t *STRING, size_t LENGTH) {
    if ($1 && $1 != tmp_buf$argnum)
        wally_free($1);
}

%apply(uint32_t *STRING, size_t LENGTH) { (const uint32_t *child_num_in, size_t child_num_len) }

%py_opaque_struct(words);
%py_opaque_struct(ext_key);

/* Tell SWIG what uint32_t means */
typedef unsigned int uint32_t;

%rename("bip32_key_from_parent") bip32_key_from_parent_alloc;
%rename("bip32_key_from_parent_path") bip32_key_from_parent_path_alloc;
%rename("bip32_key_from_seed") bip32_key_from_seed_alloc;
%rename("bip32_key_init") bip32_key_init_alloc;
%rename("bip32_key_unserialize") bip32_key_unserialize_alloc;
%rename("%(regex:/^wally_(.+)/\\1/)s", %$isfunction) "";

%include "../include/wally_core.h"
%include "../include/wally_bip32.h"
%include "bip32_int.h"
%include "../include/wally_bip38.h"
%include "../include/wally_bip39.h"
%include "../include/wally_crypto.h"
