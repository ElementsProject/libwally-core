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

WALLY_CORE_API int PyArg_ParseTuple(void *x, void *y, ...) __attribute__((weak));
int PyArg_ParseTuple(void *x, void *y, ...) { (void)x; (void)y; return 0; }
WALLY_CORE_API int PyArg_UnpackTuple(void *x, void* y, size_t z, size_t z2, ...) __attribute__((weak));
int PyArg_UnpackTuple(void *x, void* y, size_t z, size_t z2, ...) { (void)x; (void)y; (void)z; (void)z2; return 0; }
WALLY_CORE_API void * PyBool_FromLong(long x) __attribute__((weak));
void * PyBool_FromLong(long x) { (void)x; return NULL; }

WALLY_CORE_API void* PyCapsule_GetPointer(void *x, void *y) __attribute__((weak));
void* PyCapsule_GetPointer(void *x, void *y) { (void)x; return y; }
WALLY_CORE_API void* PyCapsule_Import(void *x, int y) __attribute__((weak));
void* PyCapsule_Import(void *x, int y) { (void)y; return x; }
WALLY_CORE_API void* PyCapsule_New(void *x, void* y, void *z) __attribute__((weak));
void* PyCapsule_New(void *x, void* y, void *z) { (void)x; (void)y; (void)z; return 0; }
WALLY_CORE_API void* PyDict_GetItem(void *x, void *y) __attribute__((weak));
void* PyDict_GetItem(void *x, void *y) { (void)x; return y; }

WALLY_CORE_API void * PyDict_New(void) __attribute__((weak));
void * PyDict_New(void) { return NULL; }

WALLY_CORE_API int PyDict_SetItem(void *x, void *y, void *z) __attribute__((weak));
int PyDict_SetItem(void *x, void *y, void *z) { (void)x; (void)y; (void)z; return 0; }
WALLY_CORE_API int PyDict_SetItemString(void *x, void *y, void *z) __attribute__((weak));
int PyDict_SetItemString(void *x, void *y, void *z) { (void)x; (void)y; (void)z; return 0; }
DUMMY_WEAKREF(PyErr_Clear)
DUMMY_WEAKREF(PyErr_Fetch)
DUMMY_WEAKREF(PyErr_Format)
DUMMY_WEAKREF(PyErr_Occurred)
DUMMY_WEAKREF(PyErr_Restore)
DUMMY_WEAKREF(PyErr_SetObject)
WALLY_CORE_API void PyErr_SetString(void *x, void *y) __attribute__((weak));
void PyErr_SetString(void *x, void *y) { (void)x; (void)y; }
DUMMY_WEAKREF(PyErr_WriteUnraisable)
DUMMY_WEAKREF(PyFloat_AsDouble)
WALLY_CORE_API void* PyInstance_NewRaw(void *x, void *y) __attribute__((weak));
void* PyInstance_NewRaw(void *x, void *y) { (void)x; return y; }
WALLY_CORE_API long PyInt_AsLong(void *x) __attribute__((weak));
long PyInt_AsLong(void *x) { (void)x; return 0; }
WALLY_CORE_API void * PyInt_FromLong(long x) __attribute__((weak));
void * PyInt_FromLong(long x) { (void)x; return NULL; }
WALLY_CORE_API void * PyInt_FromSize_t(size_t x) __attribute__((weak));
void * PyInt_FromSize_t(size_t x) { (void)x; return NULL; }
DUMMY_WEAKREF(PyList_Append)
DUMMY_WEAKREF(PyList_New)
DUMMY_WEAKREF(PyList_SetItem)
DUMMY_WEAKREF(PyLong_AsDouble)
WALLY_CORE_API unsigned long PyLong_AsUnsignedLong(void *x) __attribute__((weak));
unsigned long PyLong_AsUnsignedLong(void *x) { (void)x; return 0; }
DUMMY_WEAKREF(PyLong_AsUnsignedLongLong)
DUMMY_WEAKREF(PyLong_FromLong)
DUMMY_WEAKREF(PyLong_FromUnsignedLong)
WALLY_CORE_API void * PyLong_FromVoidPtr(void *x) __attribute__((weak));
void * PyLong_FromVoidPtr(void *x) { return x; }
WALLY_CORE_API int PyModule_AddObject(void *x, void *y, void *z) __attribute__((weak));
int PyModule_AddObject(void *x, void *y, void *z) { (void)x; (void)y; (void)z; return 0; }
WALLY_CORE_API void * PyModule_GetDict(void *x) __attribute__((weak));
void * PyModule_GetDict(void *x) { return x; }

DUMMY_WEAKREF(PyOS_snprintf)
WALLY_CORE_API int PyObject_AsReadBuffer(void *x, void* y, void *z) __attribute__((weak));
int PyObject_AsReadBuffer(void *x, void* y, void *z) { (void)x; (void)y; (void)z; return 0; }
WALLY_CORE_API int PyObject_AsWriteBuffer(void *x, void* y, void* z) __attribute__((weak));
int PyObject_AsWriteBuffer(void *x, void* y, void* z) { (void)x; (void)y; (void)z; return 0; }
WALLY_CORE_API void * PyObject_Call(void *x, void *y, void *z) __attribute__((weak));
void * PyObject_Call(void *x, void *y, void *z) { (void)x; (void)y; (void)z; return NULL; }
DUMMY_WEAKREF(PyObject_CallFunctionObjArgs)
WALLY_CORE_API void PyObject_Free(void *x) __attribute__((weak));
void PyObject_Free(void *x) { (void)x; }

WALLY_CORE_API void* PyObject_GenericGetAttr(void *x, void *y) __attribute__((weak));
void* PyObject_GenericGetAttr(void *x, void *y) { (void)x; return y; }
WALLY_CORE_API void* PyObject_GetAttr(void *x, void *y) __attribute__((weak));
void* PyObject_GetAttr(void *x, void *y) { (void)x; return y; }

DUMMY_WEAKREF(PyObject_GetAttrString)
WALLY_CORE_API void* PyObject_Init(void *x, void *y) __attribute__((weak));
void* PyObject_Init(void *x, void *y) { (void)x; return y; }
WALLY_CORE_API int PyObject_IsTrue(void *x) __attribute__((weak));
int PyObject_IsTrue(void *x) { (void)x; return 0; }
WALLY_CORE_API void* PyObject_Malloc(size_t x) __attribute__((weak));
void* PyObject_Malloc(size_t x) { (void)x; return NULL; }
WALLY_CORE_API void Py_DecRef(void* x) __attribute__((weak));
void Py_DecRef(void* x) { (void)x; }
DUMMY_WEAKREF(PyObject_Str)
WALLY_CORE_API void * PyString_AsString(void *x) __attribute__((weak));
void * PyString_AsString(void *x) { return x; }
WALLY_CORE_API int PyString_AsStringAndSize(void *x, void* y, void *z) __attribute__((weak));
int PyString_AsStringAndSize(void *x, void* y, void *z) { (void)x; (void)y; (void)z; return 0; }
WALLY_CORE_API void PyString_ConcatAndDel(void *x, void *y) __attribute__((weak));
void PyString_ConcatAndDel(void *x, void *y) { (void)x; (void)y; }

WALLY_CORE_API void* PyString_Format(void *x, void *y) __attribute__((weak));
void* PyString_Format(void *x, void *y) { (void)x; return y; }
DUMMY_WEAKREF(PyString_FromFormat)
WALLY_CORE_API void * PyString_FromString(void *x) __attribute__((weak));
void * PyString_FromString(void *x) { return x; }
DUMMY_WEAKREF(PyString_FromStringAndSize)
WALLY_CORE_API void * PyTuple_New(size_t x) __attribute__((weak));
void * PyTuple_New(size_t x) { (void)x; return NULL; }
WALLY_CORE_API int PyTuple_SetItem(void *x, size_t y, void *z) __attribute__((weak));
int PyTuple_SetItem(void *x, size_t y, void *z) { (void)x; (void)y; (void)z; return 0; }
DUMMY_WEAKREF(PyType_IsSubtype)
WALLY_CORE_API int PyType_Ready(void *x) __attribute__((weak));
int PyType_Ready(void *x) { (void)x; return 0; }
WALLY_CORE_API void Py_IncRef(void *x) __attribute__((weak));
void Py_IncRef(void *x) { (void)x; }
WALLY_CORE_API void* Py_InitModule4_64(void *x, void* y, void *z, void *z2, int z3) __attribute__((weak));
void* Py_InitModule4_64(void *x, void* y, void *z, void *z2, int z3) { (void)x; (void)y; (void)z; (void)z2; (void)z3; return NULL; }
WALLY_CORE_API void* _PyInstance_Lookup(void *x, void *y) __attribute__((weak));
void* _PyInstance_Lookup(void *x, void *y) { (void)x; return y; }
WALLY_CORE_API void * _PyObject_GetDictPtr(void *x) __attribute__((weak));
void * _PyObject_GetDictPtr(void *x) { return x; }

WALLY_CORE_API void * _PyObject_New(void *x) __attribute__((weak));
void * _PyObject_New(void *x) { return x; }


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
