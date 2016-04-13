%module wallycore
%{
#define SWIG_FILE_WITH_INIT
#include <stdbool.h>
#include "../include/wally-core.h"
#include "../include/wally_bip39.h"

static int check_result(int result)
{
    /* FIXME: Map error codes to exceptions
     * PyExc_ArithmeticError PyExc_AssertionError PyExc_AttributeError
     * PyExc_EnvironmentError PyExc_EOFError PyExc_Exception
     * PyExc_FloatingPointError PyExc_ImportError PyExc_IndexError
     * PyExc_IOError PyExc_KeyError PyExc_KeyboardInterrupt PyExc_LookupError
     * PyExc_MemoryError PyExc_NameError PyExc_NotImplementedError
     * PyExc_OSError PyExc_OverflowError PyExc_RuntimeError
     * PyExc_StandardError PyExc_SyntaxError PyExc_SystemError
     * PyExc_TypeError PyExc_UnicodeError PyExc_ValueError
     * PyExc_ZeroDivisionError
     */
    if (result) {
        PyErr_SetString(PyExc_RuntimeError, "Error");
    }
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


/* Input buffers with lengths are passed as python buffers */
%pybuffer_binary(const unsigned char *bytes_in, size_t len);
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
   Py_DecRef($result);
   if (*$1 == NULL) {
       Py_INCREF(Py_None);
       $result = Py_None;
   } else {
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
   Py_DecRef($result);
   if (*$1 == NULL) {
       Py_INCREF(Py_None);
       $result = Py_None;
   } else {
       $result = PyCapsule_New(*$1, NULL, NULL);
   }
}
%typemap (in) const struct NAME * {
    $1 = PyCapsule_GetPointer($input, NULL);
}
%enddef

%py_opaque_struct(words);

%include "../include/wally-core.h"
%include "../include/wally_bip39.h"
