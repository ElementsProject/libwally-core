%module wallycore
%{
#include "../include/wally_core.h"
#include "../include/wally_bip38.h"
#include "../include/wally_bip39.h"
#include "../include/wally_crypto.h"
#include <limits.h>

static int check_result(JNIEnv *jenv, int result)
{
    switch (result) {
    case WALLY_OK:
        break;
    case WALLY_EINVAL:
        SWIG_JavaThrowException(jenv, SWIG_JavaIllegalArgumentException, "Invalid argument");
        break;
    case WALLY_ENOMEM:
        SWIG_JavaThrowException(jenv, SWIG_JavaOutOfMemoryError, "Out of memory");
        break;
    default: /* WALLY_ERROR */
        SWIG_JavaThrowException(jenv, SWIG_JavaRuntimeException, "Failed");
        break;
    }
    return result;
}

static int int_cast(JNIEnv *jenv, size_t value) {
    if (value > INT_MAX)
        SWIG_JavaThrowException(jenv, SWIG_JavaIndexOutOfBoundsException, "Invalid length");
    return (int)value;
}

/* Use a static class to hold our opaque pointers */
#define OBJ_CLASS "com/blockstream/libwally/Wally$Obj"

/* Create and return a java object to hold an opaque pointer */
static jobject create_obj(JNIEnv *jenv, void* p, int id) {
    jclass clazz;
    jmethodID ctor;

    if (!(clazz = (*jenv)->FindClass(jenv, OBJ_CLASS)))
        return NULL;
    if (!(ctor = (*jenv)->GetMethodID(jenv, clazz, "<init>", "(JI)V")))
        return NULL;
    return (*jenv)->NewObject(jenv, clazz, ctor, (jlong)(uintptr_t)p, id);
}

/* Fetch an opaque pointer from a java object */
static void* get_obj(JNIEnv *jenv, jobject obj, int id) {
    jclass clazz;
    jmethodID getter;

    if (!obj || !(clazz = (*jenv)->GetObjectClass(jenv, obj)))
        return NULL;
    getter = (*jenv)->GetMethodID(jenv, clazz, "get_id", "()I");
    if (!getter || (*jenv)->CallIntMethod(jenv, obj, getter) != id)
        return NULL;
    getter = (*jenv)->GetMethodID(jenv, clazz, "get", "()J");
    return getter ? (void *)(uintptr_t)((*jenv)->CallLongMethod(jenv, obj, getter)) : NULL;
}

static void* get_obj_or_throw(JNIEnv *jenv, jobject obj, int id, const char *name) {
    void * ret = get_obj(jenv, obj, id);
    if (!ret)
        SWIG_JavaThrowException(jenv, SWIG_JavaIllegalArgumentException, name);
    return ret;
}

static unsigned char* malloc_or_throw(JNIEnv *jenv, size_t len) {
    unsigned char *p = (unsigned char *)malloc(len);
    if (!p)
        SWIG_JavaThrowException(jenv, SWIG_JavaOutOfMemoryError, "Out of memory");
    return p;
}

static jbyteArray create_array(JNIEnv *jenv, const unsigned char* p, size_t len) {
    jbyteArray ret = (*jenv)->NewByteArray(jenv, len);
    if (ret)
        (*jenv)->SetByteArrayRegion(jenv, ret, 0, len, (const jbyte*)p);
    return ret;
}
%}

%javaconst(1);
%ignore wally_free_string;
%ignore wally_bzero;

%pragma(java) jniclasscode=%{
    private static boolean loadLibrary() {
        try {
            System.loadLibrary("wallycore");
            return true;
        } catch (final UnsatisfiedLinkError e) {
            System.err.println("Native code library failed to load.\n" + e);
            return false;
        }
    }

    private static final boolean enabled = loadLibrary();
    public static boolean isEnabled() {
        return enabled;
    }

    static final class Obj {
        private final transient long ptr;
        private final int id;
        private Obj(final long ptr, final int id) { this.ptr = ptr; this.id = id; }
        private long get() { return ptr; }
        private int get_id() { return id; }
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
    $result = int_cast(jenv, *$1);
}

/* Output strings are converted to native Java strings and returned */
%typemap(in,noblock=1,numinputs=0) char **output(char *temp = 0) {
    $1 = &temp;
}
%typemap(argout,noblock=1) (char **output) {
    if ($1) {
        $result = (*jenv)->NewStringUTF(jenv, *$1);
        wally_free_string(*$1);
    } else
        $result = NULL;
}

/* Array handling */
%apply(char *STRING, size_t LENGTH) { (const unsigned char *bytes_in, size_t len_in) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char *iv, size_t iv_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char *key, size_t key_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char *pass, size_t pass_len) };
%apply(char *STRING, size_t LENGTH) { (const unsigned char *salt, size_t salt_len) };
%apply(char *STRING, size_t LENGTH) { (unsigned char *bytes_out, size_t len) };
%apply(char *STRING, size_t LENGTH) { (unsigned char *bytes_in_out, size_t len) };
%apply(char *STRING, size_t LENGTH) { (unsigned char *salt_in_out, size_t salt_len) };

/* Opaque types are converted to/from an internal object holder class */
%define %java_opaque_struct(NAME, ID)
%typemap(in, numinputs=0) const struct NAME **output (const struct NAME * w) {
    w = 0; $1 = ($1_ltype)&w;
}
%typemap(argout) const struct NAME ** {
    $result = create_obj(jenv, *$1, ID);
}
%typemap (in) const struct NAME * {
    $1 = (struct NAME *)get_obj_or_throw(jenv, $input, ID, "NAME");
    if (!$1)
        return $null;
}
%typemap(jtype) const struct NAME * "Object"
%typemap(jni) const struct NAME * "jobject"
%enddef

/* Tell SWIG what uint32_t means */
typedef unsigned int uint32_t;

/* Change a functions return type to match its output type mapping */
%define %return_decls(FUNC, JTYPE, JNITYPE)
%typemap(jstype) int FUNC "JTYPE"
%typemap(jtype) int FUNC "JTYPE"
%typemap(jni) int FUNC "JNITYPE"
%rename("%(strip:[wally_])s") FUNC;
%enddef

%define %returns_void__(FUNC)
%return_decls(FUNC, void, void)
%enddef
%define %returns_size_t(FUNC)
%return_decls(FUNC, int, jint)
%enddef
%define %returns_string(FUNC)
%return_decls(FUNC, String, jstring)
%enddef
%define %returns_struct(FUNC, STRUCT)
%return_decls(FUNC, Object, jobject)
%enddef
%define %returns_array_(FUNC, ARRAYARG, LENARG, LEN)
%return_decls(FUNC, byte[], jbyteArray)
%exception FUNC {
    if (!jarg ## ARRAYARG) {
        arg ## LENARG = LEN;
        arg ## ARRAYARG = malloc_or_throw(jenv, LEN);
        if (!arg ## ARRAYARG)
            return $null;
    }
    $action
    if (check_result(jenv, result) == WALLY_OK && !jarg ## ARRAYARG)
        jresult = create_array(jenv, arg ## ARRAYARG, LEN);
    if (!jarg ## ARRAYARG) {
        wally_bzero(arg ## ARRAYARG, LEN);
        free(arg ## ARRAYARG);
    }
}
%enddef


/* Our wrapped opaque types */
%java_opaque_struct(words, 1)

/* Our wrapped functions return types */
%returns_array_(bip38_raw_from_private_key, 6, 7, BIP38_SERIALISED_LEN);
%returns_string(bip38_from_private_key);
%returns_array_(bip38_raw_to_private_key, 6, 7, 32);
%returns_array_(bip38_to_private_key, 5, 6, 32);
%returns_string(bip39_get_languages);
%returns_struct(bip39_get_wordlist, words);
%returns_string(bip39_get_word);
%returns_string(bip39_mnemonic_from_bytes);
%returns_size_t(bip39_mnemonic_to_bytes);
%returns_void__(bip39_mnemonic_validate);
%returns_size_t(bip39_mnemonic_to_seed);
%returns_array_(wally_aes, 6, 7, AES_BLOCK_LEN);
%returns_size_t(wally_aes_cbc);
%returns_void__(wally_scrypt);
%returns_array_(wally_sha256, 3, 4, SHA256_LEN);
%returns_array_(wally_sha256d, 3, 4, SHA256_LEN);
%returns_array_(wally_sha512, 3, 4, SHA512_LEN);
%returns_array_(wally_hmac_sha256, 5, 6, HMAC_SHA256_LEN);
%returns_array_(wally_hmac_sha512, 5, 6, HMAC_SHA512_LEN);
%returns_array_(wally_pbkdf2_hmac_sha256, 7, 8, PBKDF2_HMAC_SHA256_LEN);
%returns_array_(wally_pbkdf2_hmac_sha512, 7, 8, PBKDF2_HMAC_SHA512_LEN);
%returns_void__(wally_secp_randomize);

%include "../include/wally_core.h"
%include "../include/wally_bip38.h"
%include "../include/wally_bip39.h"
%include "../include/wally_crypto.h"
