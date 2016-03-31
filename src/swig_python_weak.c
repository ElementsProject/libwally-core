/* Define weak ref implementations of the python support functions.
 *
 * This means that we can build python support directly into the
 * library without forcing the user to have python installed at
 * runtime. The weak symbols here satisfy the linker if python is
 * not used. In the event that the library is imported from python,
 * The non-weak symbols exported from python will be used instead of
 * these dummies.
 */
#include <config.h>
#include <include/wally-core.h>

#ifdef HAVE_ATTRIBUTE_WEAK

#define DUMMY_WEAKREF(func) \
    WALLY_CORE_API void func(void) __attribute__((weak)); \
    void func(void) {}

#define DUMMY_VARIABLE_WEAKREF(var) \
    WALLY_CORE_API void *var __attribute__((weak));

DUMMY_WEAKREF(PyArg_ParseTuple)
DUMMY_WEAKREF(PyArg_UnpackTuple)
DUMMY_WEAKREF(PyBool_FromLong)
DUMMY_WEAKREF(PyCapsule_GetPointer)
DUMMY_WEAKREF(PyCapsule_Import)
DUMMY_WEAKREF(PyCapsule_New)
DUMMY_WEAKREF(PyDict_GetItem)
DUMMY_WEAKREF(PyDict_New)
DUMMY_WEAKREF(PyDict_SetItem)
DUMMY_WEAKREF(PyDict_SetItemString)
DUMMY_WEAKREF(PyErr_Clear)
DUMMY_WEAKREF(PyErr_Occurred)
DUMMY_WEAKREF(PyErr_SetString)
DUMMY_VARIABLE_WEAKREF(PyExc_AttributeError)
DUMMY_VARIABLE_WEAKREF(PyExc_IOError)
DUMMY_VARIABLE_WEAKREF(PyExc_IndexError)
DUMMY_VARIABLE_WEAKREF(PyExc_MemoryError)
DUMMY_VARIABLE_WEAKREF(PyExc_OverflowError)
DUMMY_VARIABLE_WEAKREF(PyExc_RuntimeError)
DUMMY_VARIABLE_WEAKREF(PyExc_SyntaxError)
DUMMY_VARIABLE_WEAKREF(PyExc_SystemError)
DUMMY_VARIABLE_WEAKREF(PyExc_TypeError)
DUMMY_VARIABLE_WEAKREF(PyExc_ValueError)
DUMMY_VARIABLE_WEAKREF(PyExc_ZeroDivisionError)
DUMMY_WEAKREF(PyInstance_NewRaw)
DUMMY_VARIABLE_WEAKREF(PyInstance_Type)
DUMMY_WEAKREF(PyInt_AsLong)
DUMMY_WEAKREF(PyInt_FromLong)
DUMMY_WEAKREF(PyInt_FromSize_t)
DUMMY_WEAKREF(PyLong_AsUnsignedLong)
DUMMY_WEAKREF(PyLong_FromLong)
DUMMY_WEAKREF(PyLong_FromUnsignedLong)
DUMMY_WEAKREF(PyLong_FromVoidPtr)
DUMMY_WEAKREF(PyModule_AddObject)
DUMMY_WEAKREF(PyModule_GetDict)
DUMMY_WEAKREF(PyObject_AsReadBuffer)
DUMMY_WEAKREF(PyObject_AsWriteBuffer)
DUMMY_WEAKREF(PyObject_Call)
DUMMY_WEAKREF(PyObject_CallFunctionObjArgs)
DUMMY_WEAKREF(PyObject_Free)
DUMMY_WEAKREF(PyObject_GenericGetAttr)
DUMMY_WEAKREF(PyObject_GetAttr)
DUMMY_WEAKREF(PyObject_Init)
DUMMY_WEAKREF(PyObject_IsTrue)
DUMMY_WEAKREF(PyObject_Malloc)
DUMMY_WEAKREF(PyString_AsString)
DUMMY_WEAKREF(PyString_AsStringAndSize)
DUMMY_WEAKREF(PyString_ConcatAndDel)
DUMMY_WEAKREF(PyString_Format)
DUMMY_WEAKREF(PyString_FromFormat)
DUMMY_WEAKREF(PyString_FromString)
DUMMY_WEAKREF(PyString_FromStringAndSize)
DUMMY_WEAKREF(PyTuple_New)
DUMMY_WEAKREF(PyTuple_SetItem)
DUMMY_WEAKREF(PyType_Ready)
DUMMY_WEAKREF(Py_InitModule4_64)
DUMMY_WEAKREF(_PyInstance_Lookup)
DUMMY_WEAKREF(_PyObject_GetDictPtr)
DUMMY_WEAKREF(_PyObject_New)
DUMMY_VARIABLE_WEAKREF(_PyWeakref_CallableProxyType)
DUMMY_VARIABLE_WEAKREF(_PyWeakref_ProxyType)
DUMMY_VARIABLE_WEAKREF(_Py_NoneStruct)
DUMMY_VARIABLE_WEAKREF(_Py_NotImplementedStruct)
#endif /* HAVE_ATTRIBUTE_WEAK */
