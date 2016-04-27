/* Define weak ref implementations of the python support functions.
 *
 * This means that we can build python support directly into the
 * library without forcing the user to have python installed at
 * runtime. The weak symbols here satisfy the linker if python is
 * not used. In the event that the library is imported from python,
 * The non-weak symbols exported from python will be used instead of
 * these dummies.
 */
#define WALLY_CORE_BUILD 1 /* Ensure these symbols are made public */

#include <config.h>
#include <include/wally_core.h>

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
DUMMY_WEAKREF(PyErr_Fetch)
DUMMY_WEAKREF(PyErr_Format)
DUMMY_WEAKREF(PyErr_Occurred)
DUMMY_WEAKREF(PyErr_Restore)
DUMMY_WEAKREF(PyErr_SetObject)
DUMMY_WEAKREF(PyErr_SetString)
DUMMY_WEAKREF(PyErr_WriteUnraisable)
DUMMY_WEAKREF(PyFloat_AsDouble)
DUMMY_WEAKREF(PyInstance_NewRaw)
DUMMY_WEAKREF(PyInt_AsLong)
DUMMY_WEAKREF(PyInt_FromLong)
DUMMY_WEAKREF(PyInt_FromSize_t)
DUMMY_WEAKREF(PyList_Append)
DUMMY_WEAKREF(PyList_New)
DUMMY_WEAKREF(PyList_SetItem)
DUMMY_WEAKREF(PyLong_AsDouble)
DUMMY_WEAKREF(PyLong_AsUnsignedLong)
DUMMY_WEAKREF(PyLong_AsUnsignedLongLong)
DUMMY_WEAKREF(PyLong_FromLong)
DUMMY_WEAKREF(PyLong_FromUnsignedLong)
DUMMY_WEAKREF(PyLong_FromVoidPtr)
DUMMY_WEAKREF(PyModule_AddObject)
DUMMY_WEAKREF(PyModule_GetDict)
DUMMY_WEAKREF(PyOS_snprintf)
DUMMY_WEAKREF(PyObject_AsReadBuffer)
DUMMY_WEAKREF(PyObject_AsWriteBuffer)
DUMMY_WEAKREF(PyObject_Call)
DUMMY_WEAKREF(PyObject_CallFunctionObjArgs)
DUMMY_WEAKREF(PyObject_Free)
DUMMY_WEAKREF(PyObject_GenericGetAttr)
DUMMY_WEAKREF(PyObject_GetAttr)
DUMMY_WEAKREF(PyObject_GetAttrString)
DUMMY_WEAKREF(PyObject_Init)
DUMMY_WEAKREF(PyObject_IsTrue)
DUMMY_WEAKREF(PyObject_Malloc)
DUMMY_WEAKREF(PyObject_Str)
DUMMY_WEAKREF(PyString_AsString)
DUMMY_WEAKREF(PyString_AsStringAndSize)
DUMMY_WEAKREF(PyString_ConcatAndDel)
DUMMY_WEAKREF(PyString_Format)
DUMMY_WEAKREF(PyString_FromFormat)
DUMMY_WEAKREF(PyString_FromString)
DUMMY_WEAKREF(PyString_FromStringAndSize)
DUMMY_WEAKREF(PyTuple_New)
DUMMY_WEAKREF(PyTuple_SetItem)
DUMMY_WEAKREF(PyType_IsSubtype)
DUMMY_WEAKREF(PyType_Ready)
DUMMY_WEAKREF(Py_DecRef)
DUMMY_WEAKREF(Py_IncRef)
DUMMY_WEAKREF(Py_InitModule4_64)
DUMMY_WEAKREF(_PyInstance_Lookup)
DUMMY_WEAKREF(_PyObject_GetDictPtr)
DUMMY_WEAKREF(_PyObject_New)
DUMMY_VARIABLE_WEAKREF(PyCFunction_Type)
DUMMY_VARIABLE_WEAKREF(PyClass_Type)
DUMMY_VARIABLE_WEAKREF(PyFloat_Type)
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
DUMMY_VARIABLE_WEAKREF(PyInstance_Type) /* NOTE: Warnings are harmless */
DUMMY_VARIABLE_WEAKREF(_PyWeakref_CallableProxyType) /* NOTE: Warnings are harmless */
DUMMY_VARIABLE_WEAKREF(_PyWeakref_ProxyType) /* NOTE: Warnings are harmless */
DUMMY_VARIABLE_WEAKREF(_Py_NoneStruct)
DUMMY_VARIABLE_WEAKREF(_Py_NotImplementedStruct) /* NOTE: Warnings are harmless */

/* Python 3 exports */
DUMMY_VARIABLE_WEAKREF(PyBaseObject_Type)
DUMMY_WEAKREF(PyBytes_AsStringAndSize)
DUMMY_WEAKREF(PyImport_AddModule)
DUMMY_WEAKREF(PyInstanceMethod_New)
DUMMY_WEAKREF(PyLong_AsLong)
DUMMY_WEAKREF(PyLong_FromSize_t)
DUMMY_WEAKREF(PyModule_Create2)
DUMMY_WEAKREF(PyObject_IsInstance)
DUMMY_WEAKREF(PyObject_SetAttr)
DUMMY_WEAKREF(PyType_Type)
DUMMY_WEAKREF(PyUnicodeUCS4_AsUTF8String)
DUMMY_WEAKREF(PyUnicodeUCS4_Concat)
DUMMY_WEAKREF(PyUnicodeUCS4_FromFormat)
DUMMY_WEAKREF(PyUnicodeUCS4_FromString)
DUMMY_WEAKREF(PyUnicode_AsUTF8String)
DUMMY_WEAKREF(PyUnicode_Concat)
DUMMY_WEAKREF(PyUnicode_DecodeUTF8)
DUMMY_WEAKREF(PyUnicode_Format)
DUMMY_WEAKREF(PyUnicode_FromFormat)
DUMMY_WEAKREF(PyUnicode_FromString)
DUMMY_WEAKREF(PyUnicode_InternFromString)

#endif /* HAVE_ATTRIBUTE_WEAK */
