%module wallycore
%{
#include "../include/wally-core.h"
#include "../include/wally_bip39.h"

static void check_result(JNIEnv *jenv, int result) {
    if (!result)
        return;
    /* FIXME: Use result to determine exception type */
    jclass clazz = (*jenv)->FindClass(jenv, "java/lang/IllegalArgumentException");
    (*jenv)->ThrowNew(jenv, clazz, "Invalid argument");
}
%}

%javaconst(1);
%ignore wally_free_string;
%ignore wally_bzero;

%pragma(java) jniclasscode=%{
  static {
    try {
        System.loadLibrary("wallycore");
    } catch (final UnsatisfiedLinkError e) {
      System.err.println("Native code library failed to load.\n" + e);
      System.exit(1);
    }
  }
%}

/* Raise an exception whenever a function fails */
%exception {
  $action
  check_result(jenv, result);
}

/* Don't use our int return value except for exception checking */
%typemap(out) int %{
%}

/* Output parameters indicating how many bytes were written are converted
 * into return values. */
%typemap(in,noblock=1,numinputs=0) size_t *written(size_t sz) {
    sz = 0; $1 = ($1_ltype)&sz;
}
%typemap(argout,noblock=1) size_t* {
    $result = *$1;
}

/* Output strings are converted to native Java strings and returned */
%typemap(in,noblock=1,numinputs=0) char **output(char *temp = 0) {
  $1 = &temp;
}
%typemap(argout,noblock=1) (char **output) {
  if ($1) {
    $result = JCALL1(NewStringUTF, jenv, *$1);
    wally_free_string(*$1);
  } else
    $result = NULL;
}

/* Array handling */
%apply(char *STRING, size_t LENGTH) { (const unsigned char *bytes_in, size_t len) };
%apply(char *STRING, size_t LENGTH) { (unsigned char *bytes_out, size_t len) };
%apply(char *STRING, size_t LENGTH) { (unsigned char *bytes_in_out, size_t len) };

/* Opaque types are just cast to longs */
%define %java_opaque_struct(NAME)
%typemap(in, numinputs=0) const struct NAME **output (const struct NAME * w) {
   w = 0; $1 = ($1_ltype)&w;
}
%typemap(argout) const struct NAME ** {
   $result = (jlong)*$1;
}
%typemap (in) const struct NAME * {
    $1 = (struct NAME *)$input;
}
%enddef

/* Tell SWIG what uint32_t means */
typedef unsigned int uint32_t;

/* Change a functions return type to match its output type mapping */
%define %return_decls(FUNC, JTYPE, JNITYPE, RETVAL)
%typemap(jstype) int FUNC "JTYPE"
%typemap(jtype) int FUNC "JTYPE"
%typemap(jni) int FUNC "JNITYPE"
%typemap(javaout) int FUNC { return RETVAL; }
%enddef

%define %returns_void__(FUNC)
%return_decls(FUNC, void, void, /*nothing*/)
%enddef
%define %returns_size_t(FUNC)
%return_decls(FUNC, long, jlong, $jnicall)
%enddef
%define %returns_string(FUNC)
%return_decls(FUNC, String, jstring, $jnicall)
%enddef
%define %returns_struct(FUNC, STRUCT)
%return_decls(FUNC, long, jlong, /*nothing*/)
%enddef

/* Our wrapped opaque types */
%java_opaque_struct(words)

/* Our wrapped functions return types */
%returns_string(bip39_get_languages);
%returns_struct(bip39_get_wordlist, words);
%returns_string(bip39_get_word);
%returns_string(bip39_mnemonic_from_bytes);
%returns_size_t(bip39_mnemonic_to_bytes);
%returns_void__(bip39_mnemonic_validate);
%returns_size_t(bip39_mnemonic_to_seed);

%include "../include/wally-core.h"
%include "../include/wally_bip39.h"
