%module wallycore
%{
#define SWIG_FILE_WITH_INIT
#include <stdbool.h>
#include "../include/wally-core.h"
#include "../include/wally_bip39.h"
#include "../include/wally_crypto.h"

static int check_result(int result)
{
    if (!result)
        return 0;
    if (result == WALLY_EINVAL) {
        PyErr_SetString(PyExc_ValueError, "Invalid argument");
        return result;
    }
    if (result == WALLY_ENOMEM) {
        PyErr_SetString(PyExc_MemoryError, "Out of memory");
        return result;
    }
    /* WALLY_ERROR */
    PyErr_SetString(PyExc_RuntimeError, "Failed");
    return result;
}
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

/* Input buffers with lengths are passed as python buffers */
%pybuffer_binary(const unsigned char *bytes_in, size_t len);
%pybuffer_binary(const unsigned char *pass, size_t pass_len);
%pybuffer_binary(const unsigned char *salt, size_t salt_len);
%pybuffer_mutable_binary(unsigned char *bytes_in_out, size_t len);
%pybuffer_mutable_binary(unsigned char *bytes_out, size_t len);

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
       $result = PyCapsule_New(*$1, "struct NAME *", NULL);
   }
}
%typemap (in) const struct NAME * {
    $1 = PyCapsule_GetPointer($input, "struct NAME *");
}
%enddef

%py_opaque_struct(words);

%include "../include/wally-core.h"
%include "../include/wally_bip39.h"
%include "../include/wally_crypto.h"
