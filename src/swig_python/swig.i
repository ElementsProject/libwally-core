%module wallycore
%{
#define SWIG_FILE_WITH_INIT
#include <stdbool.h>
#include "../include/wally-core.h"
#include "../include/wally_bip39.h"
%}

%include typemaps.i
%include pybuffer.i
%include exception.i

/*
FIXME: Map error codes to exceptions
PyExc_ArithmeticError
PyExc_AssertionError
PyExc_AttributeError
PyExc_EnvironmentError
PyExc_EOFError
PyExc_Exception
PyExc_FloatingPointError
PyExc_ImportError
PyExc_IndexError
PyExc_IOError
PyExc_KeyError
PyExc_KeyboardInterrupt
PyExc_LookupError
PyExc_MemoryError
PyExc_NameError
PyExc_NotImplementedError
PyExc_OSError
PyExc_OverflowError
PyExc_RuntimeError
PyExc_StandardError
PyExc_SyntaxError
PyExc_SystemError
PyExc_TypeError
PyExc_UnicodeError
PyExc_ValueError
PyExc_ZeroDivisionError
*/

/* Raise an exception whenever a function fails */
%exception{
    $action
    if (result) {
        PyErr_SetString(PyExc_RuntimeError, "Error");
        SWIG_fail;
    }
};


/* Input buffers with lengths are passed as python buffers */
%pybuffer_binary(const unsigned char *bytes_in, size_t len);
%pybuffer_mutable_binary(unsigned char *bytes_in_out, size_t len);
%pybuffer_mutable_binary(unsigned char *bytes_out, size_t len);

/* Output parameters indicating how many bytes were written are converted
 * into return values. */
%apply size_t *OUTPUT { size_t *written };

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

/* Opaque types are passed along as capsules FIXME: Generalise */
%typemap(in, numinputs=0) const struct words **output (struct words * w) {
   w = 0; $1 = ($1_ltype)&w;
}
%typemap(argout) const struct words ** {
   Py_DecRef($result);
   if (*$1 == NULL) {
       Py_INCREF(Py_None);
       //$result = SWIG_Python_AppendOutput($result, Py_None);
       $result = Py_None;
   } else {
       $result = PyCapsule_New(*$1, NULL, NULL);
   }
}

%typemap (in) const struct words *
{
    $1 = PyCapsule_GetPointer($input, NULL);
}

%include "../include/wally-core.h"
%include "../include/wally_bip39.h"
