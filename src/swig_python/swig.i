/*
 * The automatic module importing varies between Swig3 and Swig4.
 * Make explicit so should work for both versions.
 * (Basically the swig3 version).
 */
%define MODULEIMPORT
"
def swig_import_helper():
    import importlib
    pkg = __name__.rpartition('.')[0]
    mname = '.'.join((pkg, '$module')).lstrip('.')
    try:
        return importlib.import_module(mname)
    except ImportError:
        return importlib.import_module('$module')
$module = swig_import_helper()
del swig_import_helper
"
%enddef
%module(moduleimport=MODULEIMPORT) wallycore
%{
#define SWIG_FILE_WITH_INIT
#include <stdbool.h>
#include "../include/wally_core.h"
#include "../include/wally_address.h"
#include "../include/wally_anti_exfil.h"
#include "../include/wally_bip32.h"
#include "bip32_int.h"
#include "../include/wally_bip38.h"
#include "../include/wally_bip39.h"
#include "../include/wally_bip85.h"
#include "../include/wally_coinselection.h"
#include "../include/wally_crypto.h"
#include "../include/wally_descriptor.h"
#include "../include/wally_map.h"
#include "../include/wally_psbt.h"
#include "../include/wally_psbt_members.h"
#include "../include/wally_script.h"
#include "../include/wally_symmetric.h"
#include "../include/wally_transaction.h"
#include "transaction_int.h"
#include "../include/wally_elements.h"
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

static bool size_t_cast(PyObject *item, size_t *val)
{
    if (PyLong_Check(item)) {
        *val = PyLong_AsSize_t(item);
        if (!PyErr_Occurred())
          return true;
        PyErr_Clear();
    }
    return false;
}

static bool ulonglong_cast(PyObject *item, unsigned long long *val)
{
    if (PyLong_Check(item)) {
        *val = PyLong_AsUnsignedLongLong(item);
        if (!PyErr_Occurred())
          return true;
        PyErr_Clear();
    }
    return false;
}

#define capsule_dtor(name, fn) static void destroy_##name(PyObject *obj) { \
    struct name *p = obj == Py_None ? NULL : (struct name *)PyCapsule_GetPointer(obj, "struct " #name " *"); \
    if (p) fn(p); }

capsule_dtor(ext_key, bip32_key_free)
capsule_dtor(wally_descriptor, wally_descriptor_free)
capsule_dtor(wally_psbt, wally_psbt_free)
capsule_dtor(wally_tx, wally_tx_free)
capsule_dtor(wally_tx_input, wally_tx_input_free)
capsule_dtor(wally_tx_output, wally_tx_output_free)
capsule_dtor(wally_tx_witness_stack, wally_tx_witness_stack_free)
capsule_dtor(wally_map, wally_map_free)
static void destroy_words(PyObject *obj) { (void)obj; }

#define MAX_LOCAL_STACK 256u
%}

%include pybuffer.i
%include exception.i
%include stdint.i

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

/*
 * The behaviour of pybuffer_binary varies wrt a Py_None argument between Swig3
 * (raises TypeError) and Swig4 (passes through as NULL) - so make explicit
 * 'nullable' macro for consistent behaviour (passing NULL) across versions.
 * NOTE: the code in the 'else' branch is essentially taken from swig4's
 * pybuffer_binary macro implementation.
 * Note local fix for: https://github.com/swig/swig/issues/1640
 */
%define %pybuffer_nullable_binary(TYPEMAP, SIZE)
%typemap(in) (TYPEMAP, SIZE) {
  int res; Py_ssize_t size = 0; const void *buf = 0;
  Py_buffer view;
  if ($input == Py_None)
    $2 = 0;
  else {
    res = PyObject_GetBuffer($input, &view, PyBUF_CONTIG_RO);
    if (res < 0) {
      PyErr_Clear();
      %argument_fail(res, "(TYPEMAP, SIZE)", $symname, $argnum);
    }
    size = view.len;
    buf = view.buf;
    PyBuffer_Release(&view);
    $1 = ($1_ltype) buf;
    $2 = ($2_ltype) (size / sizeof($*1_type));
  }
}
%enddef

/*
 * This is a copy of swig4's 'pybuffer_mutable_binary' but with the
 * call to PyBuffer_Release() only made if the call to PyObject_GetBuffer()
 * returned 0 (ie. succeeded).
 * FIXME: Remove in favour of pybuffer_mutable_binary when:
 * a) we move to swig4
 * b) the call to Release() is fixed upstream
 * see: https://github.com/swig/swig/issues/1640
 */
%define %pybuffer_output_binary(TYPEMAP, SIZE)
%typemap(in) (TYPEMAP, SIZE) {
  int res; Py_ssize_t size = 0; void *buf = 0;
  Py_buffer view;
  res = PyObject_GetBuffer($input, &view, PyBUF_WRITABLE);
  if (res < 0) {
    PyErr_Clear();
    %argument_fail(res, "(TYPEMAP, SIZE)", $symname, $argnum);
  }
  size = view.len;
  buf = view.buf;
  PyBuffer_Release(&view);
  $1 = ($1_ltype) buf;
  $2 = ($2_ltype) (size/sizeof($*1_type));
}
%enddef

/* Output integer values are converted into return values. */
%typemap(in, numinputs=0, noblock=1) size_t *written {
   size_t written = 0; $1 = ($1_ltype)&written;
}
%typemap(argout) size_t* written {
   Py_DecRef($result);
   $result = PyInt_FromSize_t(*$1);
}

%typemap(in, numinputs=0) uint32_t *value_out (uint32_t val) {
   val = 0; $1 = ($1_ltype)&val;
}
%typemap(argout) uint32_t* value_out{
   Py_DecRef($result);
   $result = PyLong_FromUnsignedLong(*$1);
}

%typemap(in, numinputs=0) uint64_t *value_out (uint64_t val) {
   val = 0; $1 = ($1_ltype)&val;
}
%typemap(argout) uint64_t* value_out{
   Py_DecRef($result);
   $result = PyLong_FromUnsignedLongLong(*$1);
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

/* Output string arrays are converted to a native python string list and returned */
%typemap(in) (char** output, size_t num_outputs) {
    if (!size_t_cast($input, &$2)) {
        PyErr_SetString(PyExc_OverflowError, "Invalid output size");
        SWIG_fail;
    }
    $1 = (void *) wally_malloc($2 * sizeof(char*));
}
%typemap(argout) (char** output, size_t num_outputs) {
   if ($1 != NULL) {
       size_t i;
       Py_DecRef($result);
       $result = PyList_New($2);
       for (i = 0; i < $2; i++) {
           PyObject *s = PyString_FromString($1[i]);
           PyList_SetItem($result, i, s);
           wally_free_string($1[i]);
       }
       wally_free($1);
   }
}

/* Opaque types are passed along as capsules */
%define %py_opaque_struct(NAME)
%typemap(in, numinputs=0) struct NAME **output (struct NAME * w) {
   w = 0; $1 = ($1_ltype)&w;
}
%typemap(argout) struct NAME ** {
   if (*$1 != NULL) {
       Py_DecRef($result);
       $result = PyCapsule_New(*$1, "struct NAME *", destroy_ ## NAME);
   }
}
%typemap (in) const struct NAME * {
    $1 = $input == Py_None ? NULL : PyCapsule_GetPointer($input, "struct NAME *");
    if (PyErr_Occurred()) {
        PyErr_Clear();
        %argument_fail(-1, "(NAME)", $symname, $argnum);
    }
}
%typemap (in) struct NAME * {
    $1 = $input == Py_None ? NULL : PyCapsule_GetPointer($input, "struct NAME *");
    if (PyErr_Occurred()) {
        PyErr_Clear();
        %argument_fail(-1, "(NAME)", $symname, $argnum);
    }
}
%enddef

/* Integer arrays */
%define %py_int_array(INTTYPE, INTMAX, PNAME, LNAME)
%typemap(in) (const INTTYPE *PNAME, size_t LNAME) (INTTYPE tmp_buf[MAX_LOCAL_STACK/sizeof(INTTYPE)]) {
   size_t i;
   if (!PyList_Check($input)) {
       check_result(WALLY_EINVAL);
       SWIG_fail;
   }
   $2 = PyList_Size($input);
   $1 = tmp_buf;
   if ($2 * sizeof(INTTYPE) > sizeof(tmp_buf))
       if (!($1 = (INTTYPE *) wally_malloc(($2) * sizeof(INTTYPE)))) {
           check_result(WALLY_ENOMEM);
           SWIG_fail;
       }
   for (i = 0; i < $2; ++i) {
       PyObject *item = PyList_GET_ITEM($input, i);
       unsigned long long v;
       if (!ulonglong_cast(item, &v) || v > INTMAX) {
           PyErr_SetString(PyExc_OverflowError, "Invalid unsigned integer");
           SWIG_fail;
       }
       $1[i] = (INTTYPE)v;
   }
}
%typemap(freearg) (const INTTYPE *PNAME, size_t LNAME) {
    if ($1 && $1 != tmp_buf$argnum)
        wally_free($1);
}
%enddef

/* output integer arrays take a list of the desired size and populate it */
%define %py_int_array_out(INTTYPE, INTMAX, PNAME, LNAME)
%typemap(in) (INTTYPE *PNAME, size_t LNAME) (INTTYPE tmp_buf[MAX_LOCAL_STACK/sizeof(INTTYPE)]) {
   if (!PyList_CheckExact($input)) {
       check_result(WALLY_EINVAL);
       SWIG_fail;
   }
   $2 = PyList_Size($input);
   $1 = tmp_buf;
   if ($2 * sizeof(INTTYPE) > sizeof(tmp_buf)) {
       if (!($1 = (INTTYPE *) wally_malloc($2 * sizeof(INTTYPE)))) {
           check_result(WALLY_ENOMEM);
           SWIG_fail;
       }
   }
}
%typemap(argout) (INTTYPE *PNAME, size_t LNAME) {
    if ($2 && PyList_SetSlice($input, 0, $2, NULL))
        SWIG_fail;
    if (written <= $2) {
        for (size_t i = 0; i < written; ++i) {
            PyObject* p = PyLong_FromUnsignedLong($1[i]);
            if (PyList_Append($input, p)) {
                PyList_SetSlice($input, 0, PyList_Size($input), NULL);
                SWIG_fail;
            }
        }
    }
}
%typemap(freearg) (INTTYPE *PNAME, size_t LNAME) {
    if ($1 && $1 != tmp_buf$argnum)
        wally_free($1);
}
%enddef

/* BEGIN AUTOGENERATED */
%pybuffer_nullable_binary(const unsigned char* abf, size_t abf_len);
%pybuffer_nullable_binary(const unsigned char* annex, size_t annex_len);
%pybuffer_nullable_binary(const unsigned char* asset, size_t asset_len);
%pybuffer_nullable_binary(const unsigned char* aux_rand, size_t aux_rand_len);
%pybuffer_nullable_binary(const unsigned char* blinding_nonce, size_t blinding_nonce_len);
%pybuffer_nullable_binary(const unsigned char* bytes, size_t bytes_len);
%pybuffer_nullable_binary(const unsigned char* chain_code, size_t chain_code_len);
%pybuffer_nullable_binary(const unsigned char* commitment, size_t commitment_len);
%pybuffer_nullable_binary(const unsigned char* contract_hash, size_t contract_hash_len);
%pybuffer_nullable_binary(const unsigned char* entropy, size_t entropy_len);
%pybuffer_nullable_binary(const unsigned char* extra, size_t extra_len);
%pybuffer_nullable_binary(const unsigned char* final_scriptsig, size_t final_scriptsig_len);
%pybuffer_nullable_binary(const unsigned char* fingerprint, size_t fingerprint_len);
%pybuffer_nullable_binary(const unsigned char* generator, size_t generator_len);
%pybuffer_nullable_binary(const unsigned char* genesis_blockhash, size_t genesis_blockhash_len);
%pybuffer_nullable_binary(const unsigned char* hash160, size_t hash160_len);
%pybuffer_nullable_binary(const unsigned char* hash_prevouts, size_t hash_prevouts_len);
%pybuffer_nullable_binary(const unsigned char* hmac_key, size_t hmac_key_len);
%pybuffer_nullable_binary(const unsigned char* inflation_keys, size_t inflation_keys_len);
%pybuffer_nullable_binary(const unsigned char* inflation_keys_rangeproof, size_t inflation_keys_rangeproof_len);
%pybuffer_nullable_binary(const unsigned char* issuance_amount, size_t issuance_amount_len);
%pybuffer_nullable_binary(const unsigned char* issuance_amount_rangeproof, size_t issuance_amount_rangeproof_len);
%pybuffer_nullable_binary(const unsigned char* iv, size_t iv_len);
%pybuffer_nullable_binary(const unsigned char* key, size_t key_len);
%pybuffer_nullable_binary(const unsigned char* label, size_t label_len);
%pybuffer_nullable_binary(const unsigned char* mainchain_script, size_t mainchain_script_len);
%pybuffer_nullable_binary(const unsigned char* merkle_hashes, size_t merkle_hashes_len);
%pybuffer_nullable_binary(const unsigned char* merkle_root, size_t merkle_root_len);
%pybuffer_nullable_binary(const unsigned char* nonce, size_t nonce_len);
%pybuffer_nullable_binary(const unsigned char* nonce_hash, size_t nonce_hash_len);
%pybuffer_nullable_binary(const unsigned char* offline_keys, size_t offline_keys_len);
%pybuffer_nullable_binary(const unsigned char* online_keys, size_t online_keys_len);
%pybuffer_nullable_binary(const unsigned char* online_priv_key, size_t online_priv_key_len);
%pybuffer_nullable_binary(const unsigned char* operand, size_t operand_len);
%pybuffer_nullable_binary(const unsigned char* output_abf, size_t output_abf_len);
%pybuffer_nullable_binary(const unsigned char* output_asset, size_t output_asset_len);
%pybuffer_nullable_binary(const unsigned char* output_generator, size_t output_generator_len);
%pybuffer_nullable_binary(const unsigned char* parent160, size_t parent160_len);
%pybuffer_nullable_binary(const unsigned char* pass, size_t pass_len);
%pybuffer_nullable_binary(const unsigned char* priv_key, size_t priv_key_len);
%pybuffer_nullable_binary(const unsigned char* proof, size_t proof_len);
%pybuffer_nullable_binary(const unsigned char* pub_key, size_t pub_key_len);
%pybuffer_nullable_binary(const unsigned char* rangeproof, size_t rangeproof_len);
%pybuffer_nullable_binary(const unsigned char* redeem_script, size_t redeem_script_len);
%pybuffer_nullable_binary(const unsigned char* s2c_data, size_t s2c_data_len);
%pybuffer_nullable_binary(const unsigned char* s2c_opening, size_t s2c_opening_len);
%pybuffer_nullable_binary(const unsigned char* salt, size_t salt_len);
%pybuffer_nullable_binary(const unsigned char* scalar, size_t scalar_len);
%pybuffer_nullable_binary(const unsigned char* script, size_t script_len);
%pybuffer_nullable_binary(const unsigned char* scriptpubkey, size_t scriptpubkey_len);
%pybuffer_nullable_binary(const unsigned char* sig, size_t sig_len);
%pybuffer_nullable_binary(const unsigned char* sub_pubkey, size_t sub_pubkey_len);
%pybuffer_nullable_binary(const unsigned char* summed_key, size_t summed_key_len);
%pybuffer_nullable_binary(const unsigned char* surjectionproof, size_t surjectionproof_len);
%pybuffer_nullable_binary(const unsigned char* tap_sig, size_t tap_sig_len);
%pybuffer_nullable_binary(const unsigned char* tapleaf_hashes, size_t tapleaf_hashes_len);
%pybuffer_nullable_binary(const unsigned char* tapleaf_script, size_t tapleaf_script_len);
%pybuffer_nullable_binary(const unsigned char* txhash, size_t txhash_len);
%pybuffer_nullable_binary(const unsigned char* txhashes, size_t txhashes_len);
%pybuffer_nullable_binary(const unsigned char* txout_proof, size_t txout_proof_len);
%pybuffer_nullable_binary(const unsigned char* val, size_t val_len);
%pybuffer_nullable_binary(const unsigned char* value, size_t value_len);
%pybuffer_nullable_binary(const unsigned char* vbf, size_t vbf_len);
%pybuffer_nullable_binary(const unsigned char* whitelistproof, size_t whitelistproof_len);
%pybuffer_nullable_binary(const unsigned char* witness, size_t witness_len);
%pybuffer_output_binary(unsigned char* abf_out, size_t abf_out_len);
%pybuffer_output_binary(unsigned char* asset_out, size_t asset_out_len);
%pybuffer_output_binary(unsigned char* bytes_out, size_t len);
%pybuffer_output_binary(unsigned char* s2c_opening_out, size_t s2c_opening_out_len);
%pybuffer_output_binary(unsigned char* scalar, size_t scalar_len);
%pybuffer_output_binary(unsigned char* vbf_out, size_t vbf_out_len);
%ignore bip32_key_from_base58;
%ignore bip32_key_from_base58_n;
%ignore bip32_key_from_parent;
%ignore bip32_key_from_parent_path;
%ignore bip32_key_from_parent_path_str;
%ignore bip32_key_from_parent_path_str_n;
%ignore bip32_key_from_seed;
%ignore bip32_key_from_seed_custom;
%ignore bip32_key_init;
%ignore bip32_key_unserialize;
%ignore bip32_key_with_tweak_from_parent_path;
%ignore wally_map_init;
%ignore wally_psbt_blind;
%ignore wally_psbt_get_input_best_utxo;
%ignore wally_tx_elements_output_init;
%ignore wally_tx_output_clone;
%ignore wally_tx_output_init;
/* END AUTOGENERATED */

%py_int_array(uint32_t, 0xffffffffull, child_path, child_path_len)
%py_int_array(uint32_t, 0xffull, sighash, sighash_len)
%py_int_array(uint32_t, 0xffffffffull, utxo_indices, num_utxo_indices)
%py_int_array(uint64_t, 0xffffffffffffffffull, values, num_values)
%py_int_array_out(uint32_t, 0xffffffffull, child_path_out, child_path_out_len)
%py_int_array_out(uint32_t, 0xffffffffull, indices_out, indices_out_len)

%py_opaque_struct(ext_key);
%py_opaque_struct(wally_descriptor);
%py_opaque_struct(wally_psbt);
%py_opaque_struct(wally_tx);
%py_opaque_struct(wally_tx_input);
%py_opaque_struct(wally_tx_output);
%py_opaque_struct(wally_tx_witness_stack);
%py_opaque_struct(wally_map)
%py_opaque_struct(words);

%rename("%(regex:/^wally_(.+)/\\1/)s", %$isfunction) "";

%include "../include/wally_core.h"
%include "../include/wally_address.h"
%include "../include/wally_anti_exfil.h"
%include "../include/wally_bip32.h"
%include "bip32_int.h"
%include "../include/wally_bip38.h"
%include "../include/wally_bip39.h"
%include "../include/wally_bip85.h"
%include "../include/wally_coinselection.h"
%include "../include/wally_crypto.h"
%include "../include/wally_descriptor.h"
%include "../include/wally_map.h"
%include "../include/wally_psbt.h"
%include "../include/wally_psbt_members.h"
%include "../include/wally_script.h"
%include "../include/wally_symmetric.h"
%include "../include/wally_transaction.h"
%include "transaction_int.h"
%include "../include/wally_elements.h"
