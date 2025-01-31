#!/usr/bin/env python3
import os
import subprocess
import sys

# Structs with no definition in the public header files
OPAQUE_STRUCTS = [u'words', u'wally_descriptor']

EXCLUDED_FUNCS = {
    # Callers should use the fixed length bip39_mnemonic_to_seed512
    'bip39_mnemonic_to_seed',
    # Callers should use the non-in-place, value returning scalar operations
    'wally_ec_scalar_add_to', 'wally_ec_scalar_multiply_by',
    'wally_ec_scalar_subtract_from',
    # Map getters returning internal pointers are only for C/C++ use
    'wally_map_get', 'wally_map_get_integer',
}

# BIP38's Scrypt can't work due to WASM's memory restrictions
WASM_EXCLUDED_FUNCS = EXCLUDED_FUNCS | {
    'bip38_from_private_key', 'bip38_raw_from_private_key',
    'bip38_raw_to_private_key', 'bip38_to_private_key',
}

# Output buffer length functions that aren't yet part of the API
# The boolean is whether the length function is a maximum length,
# True = Yes, False = Exact length
MISSING_LEN_FUNCS = {
    'wally_base58_to_bytes': True,
    'wally_base58_n_to_bytes': True,
    'wally_elements_pegin_contract_script_from_bytes': True,
    'wally_elements_pegout_script_from_bytes': True,
    'wally_format_bitcoin_message': True,
    'wally_hex_n_to_bytes': False,
    'wally_hex_to_bytes': False,
    'wally_script_push_from_bytes': True,
    'wally_scriptpubkey_csv_2of2_then_1_from_bytes': True,
    'wally_scriptpubkey_csv_2of2_then_1_from_bytes_opt': True,
    'wally_scriptpubkey_multisig_from_bytes': True,
    'wally_scriptsig_multisig_from_bytes': True,
    'wally_wif_to_public_key': False,
}

def replace_text(filename, text, delims):
    lines = [line.rstrip() for line in open(filename)]
    start, end = lines.index(delims[0]), lines.index(delims[1])
    replaced = lines[:start + 1] + text + lines[end:]
    replaced = [l + u'\n' for l in replaced]
    open(filename, u'w').writelines([l for l in replaced])

def get_non_elements_functions():
    # SWIG_PYTHON_BUILD=1 used to include internal functions too
    cmd = "-E -DWALLY_ABI_NO_ELEMENTS=1 -DSWIG_PYTHON_BUILD=1 include/*.h src/bip32_int.h |" \
          "sort | uniq | sed 's/^ *WALLY_CORE_API//' | grep '^ *int ' | grep '(' | sed -e 's/^ *int //g' -e 's/(.*//g' | egrep '^wally_|^bip'"
    try:
        funcs = subprocess.check_output(u'gcc ' + cmd, shell=True)
    except subprocess.CalledProcessError:
        funcs = subprocess.check_output(u'clang ' + cmd, shell=True)
    return funcs.decode('utf-8').split(u'\n')

def strip_wally_prefix(func_name):
    return func_name[len('wally_'):] if func_name.startswith('wally_') else func_name

def get_export_name(func_name, all_names):
    # Strip the '_alloc' suffix (this is typically what the user wants)
    if func_name.endswith("_alloc"):
        func_name = func_name[0:-6]
    # Add '_noalloc' suffix to the non-alloc variation (should be used rarely)
    elif f"{func_name}_alloc" in all_names:
        func_name = f"{func_name}_noalloc"
    # Strip 'wally_' prefix to keep things DRY
    return strip_wally_prefix(func_name)

def map_ignored(func, all_funcs):
    # wrappers expose foo_alloc() as foo(); hide any non-alloc version
    return f'%ignore {func.name};' if func.name + '_alloc' in all_funcs else ''

class Arg(object):
    def __init__(self, definition):
        if u'*' in definition:
            self.is_pointer = True
            self.is_pointer_pointer = u'**' in definition
            if self.is_pointer_pointer:
                self.type = definition.split(' **')[0] + '**'
            else:
                self.type = definition.split(' *')[0] + '*'
            self.name = definition[len(self.type) + 1:]
            self.is_struct = u'struct' in self.type
            if self.is_struct:
                self.struct_name = self.type.split(u' ')[-1].split(u'*')[0]
                self.is_opaque = self.struct_name in OPAQUE_STRUCTS
        else:
            self.is_pointer = False
            self.is_pointer_pointer = False
            self.is_struct = False
            self.type, self.name = definition.split(' ')
        self.docs = ''
        self.is_const = self.type.startswith(u'const ')
        self.fixed_size = None
        self.max_size = None

    def add_metadata(self, m):
        if 'FIXED_SIZED_OUTPUT(' in m:
            parts = [p.strip() for p in m[len('FIXED_SIZED_OUTPUT('):-1].split(',')]
            self.fixed_size = parts[2]
        elif 'MAX_SIZED_OUTPUT(' in m:
            parts = [p.strip() for p in m[len('MAX_SIZED_OUTPUT('):-1].split(',')]
            self.max_size = parts[2]
        else:
            assert m.startswith(':param '), 'Unknown metadata format {}'.format(m)
            assert not self.docs, self.name + ': unexpected extra docs: ' + m
            self.docs = m.split(':')[-1].strip()

class Func(object):
    def __init__(self, definition, non_elements):
        # Strip return type and closing ')', extract name
        try:
            self.name, definition = definition[4:-1].split(u'(')
        except ValueError:
            raise Exception('failed to parse definition ' + definition)
        # Parse arguments
        self.args = [Arg(d) for d in definition.split(u', ')]
        self.is_elements = self.name not in non_elements
        self.docs = []
        self.buffer_len_fn = None
        self.buffer_len_is_upper_bound = None

    def __lt__(self, other):
        return self.name < other.name

    def add_metadata(self, m):
        if m.startswith(u'FIXED_SIZED_OUTPUT(') or m.startswith(u'MAX_SIZED_OUTPUT('):
            arg_name = m.split('(')[1].split(',')[0].strip() # Argument metadata
        elif m.startswith(':param '):
            arg_name = m[len(':param '):].split(':')[0] # Argument docs
        else:
            self.docs.append(m) # Function docs
            return
        args = [arg for arg in self.args if arg.name == arg_name]
        assert len(args) == 1, self.name + ':' + arg_name + \
                ': invalid metadata reference {}'.format(m) + ' refs: ' + str(len(args))
        args[0].add_metadata(m)


def is_array(func, arg, n, num_args, types):
    return arg.type in types and n != num_args -1 and \
               func.args[n + 1].type == u'size_t' and \
               (func.args[n + 1].name.endswith(u'len') or
                func.args[n + 1].name.startswith(u'num_'))


def is_buffer(func, arg, n, num_args):
    return is_array(func, arg, n, num_args, [u'const unsigned char*', u'unsigned char*'])


def is_int_buffer(func, arg, n, num_args):
    return is_array(func, arg, n, num_args, [u'const uint32_t*', u'const uint64_t*'])


def gen_python_cffi(funcs, all_funcs, internal_only):
    typemap = {
        u'int'           : u'c_int',
        u'size_t*'       : u'c_size_t_p',
        u'size_t'        : u'c_size_t',
        u'uint32_t*'     : u'c_uint32_p',
        u'uint32_t'      : u'c_uint32',
        u'uint64_t*'     : u'c_uint64_p',
        u'uint64_t'      : u'c_uint64',
        u'void**'        : u'POINTER(c_void_p)',
        u'void*'         : u'c_void_p',
        u'unsigned char*': u'c_void_p',
        u'char**'        : u'c_char_p_p',
        u'char*'         : u'c_char_p',
        u'wally_map_verify_fn_t' : u'c_void_p',
        }
    def map_arg(arg, n, num_args):
        argtype = arg.type[6:] if arg.is_const else arg.type # Strip const
        if argtype == u'uint32_t*' and n != num_args - 1:
            return u'POINTER(c_uint32)'
        if argtype == u'uint64_t*' and n != num_args - 1:
            return u'POINTER(c_uint64)'
        if argtype == u'char**' and n != num_args - 1:
            return u'POINTER(c_char_p)'
        if argtype in typemap:
            return typemap[argtype]
        if arg.is_struct:
            if arg.is_opaque:
                return typemap[u'void**' if arg.is_pointer_pointer else u'void*']
            text = f'POINTER({arg.struct_name})'
            if arg.is_pointer_pointer:
                text = f'POINTER({text})'
            return text
        assert False, f'ERROR: Unknown argument type "{argtype}"'

    cffi = []
    for func in funcs:
        num_args = len(func.args)
        mapped = u', '.join([map_arg(arg, i, num_args) for i, arg in enumerate(func.args)])
        cffi.append(f"    ('{func.name}', c_int, [{mapped}]),")

    cffi.sort()
    if internal_only:
        markers = [u'    # BEGIN INTERNAL AUTOGENERATED', u'    # END INTERNAL AUTOGENERATED']
    else:
        markers = [u'    # BEGIN AUTOGENERATED', u'    # END AUTOGENERATED']
    replace_text(u'src/test/util.py', cffi, markers)


def gen_python_swig(funcs, all_funcs):
    output_arrays = {
        'unsigned char*' : '_wrap_bin',
        'uint32_t*'      : '_wrap_int_array',
    }

    def map_arg(func, arg, n, num_args):
        if is_buffer(func, arg, n, num_args):
            macro = u'output' if arg.type == u'unsigned char*' else u'nullable'
            return f'%pybuffer_{macro}_binary({arg.type} {arg.name}, size_t {func.args[n + 1].name});'
        return u''

    def wrap_output_buffers(func, num_args):
        if func.name in EXCLUDED_FUNCS or func.name == 'wally_s2c_sig_from_bytes':
            return ''
        func_name = get_export_name(func.name, all_funcs)
        if func.name.endswith('_alloc'):
            return f'{func_name} = {func_name}_alloc'
        if num_args > 2:
            last_arg, buf_index = func.args[num_args-1], num_args-2
            is_variable = last_arg.type == u'size_t*' and last_arg.name == u'written'
            if is_variable:
                last_arg = func.args[num_args-2]
                buf_index = num_args - 3
            if buf_index < 0:
                return ''
            buf_arg = func.args[buf_index]
            if not is_array(func, buf_arg, buf_index, num_args, output_arrays.keys()):
                return ''
            wrap_fn = output_arrays[buf_arg.type]
            if func.name in MISSING_LEN_FUNCS:
                len_fn = strip_wally_prefix(func.name) + '_len'
                resize = ', resize=True' if MISSING_LEN_FUNCS[func.name] else ''
                return f'{func_name} = {wrap_fn}({func_name}, {len_fn}{resize})'
            elif last_arg.fixed_size:
                return f'{func_name} = {wrap_fn}({func_name}, {last_arg.fixed_size})'
            elif last_arg.max_size:
                return f'{func_name} = {wrap_fn}({func_name}, {last_arg.max_size}, resize=True)'
            elif func.buffer_len_fn:
                len_fn = get_export_name(func.buffer_len_fn, all_funcs)
                resize = ', resize=True' if func.buffer_len_is_upper_bound else ''
                return f'{func_name} = {wrap_fn}({func_name}, {len_fn}{resize})'
        return ''

    buffer_args, ignored_calls, wrapped_calls, wrapped_liquid_calls = [], [], [], []
    for func in funcs:
        num_args = len(func.args)
        mapped = [map_arg(func, arg, i, num_args) for i, arg in enumerate(func.args)]
        buffer_args.extend([m for m in mapped if m])
        ignored_calls.extend([m for m in [map_ignored(func, all_funcs)] if m])
        wrapped = wrap_output_buffers(func, num_args)
        if wrapped:
            [wrapped_calls, wrapped_liquid_calls][func.is_elements].append(wrapped)

    swig_i_decls = sorted(set(buffer_args)) + sorted(set(ignored_calls))
    replace_text(u'src/swig_python/swig.i', swig_i_decls,
                 [u'/* BEGIN AUTOGENERATED */', u'/* END AUTOGENERATED */'])
    wrapped_calls.sort()
    wrapped_liquid_calls.sort()
    wrapped_liquid_calls = ['if is_elements_build():'] + \
        ['    ' + call for call in wrapped_liquid_calls]
    calls = wrapped_calls + wrapped_liquid_calls
    replace_text(u'src/swig_python/python_extra.py_in', calls,
                 [u'# BEGIN AUTOGENERATED', u'# END AUTOGENERATED'])


def gen_java_swig(funcs, all_funcs):
    def map_arg(func, arg, n, num_args):
        if is_buffer(func, arg, n, num_args):
            return f'%apply(char *STRING, size_t LENGTH) {{ ({arg.type} {arg.name}, size_t {func.args[n + 1].name}) }};'
        return u''

        ignored_calls.extend([m for m in [map_ignored(func, all_funcs)] if m])
    buffer_args, ignored_calls = [], []
    for func in funcs:
        num_args = len(func.args)
        mapped = [map_arg(func, arg, i, num_args) for i, arg in enumerate(func.args)]
        buffer_args.extend([m for m in mapped if m])
        ignored_calls.extend([m for m in [map_ignored(func, all_funcs)] if m])

    swig_i_decls = sorted(set(buffer_args)) + sorted(set(ignored_calls))
    replace_text(u'src/swig_java/swig.i', swig_i_decls,
                 [u'/* BEGIN AUTOGENERATED */', u'/* END AUTOGENERATED */'])


def gen_wally_hpp(funcs, all_funcs):
    cpp, cpp_elements = {}, {}
    for func in funcs:
        num_args = len(func.args)
        vardecl = ''
        t_types, cpp_args, call_args = [], [], []
        skip = False
        for n, arg in enumerate(func.args):
            if skip:
                skip = False
                continue
            is_verify_function = func.name.endswith('_verify')
            if is_buffer(func, arg, n, num_args) or is_int_buffer(func, arg, n, num_args):
                t_types.append(f'class {arg.name.upper()}')
                const = u'const ' if arg.is_const else ''
                cpp_args.append(f'{const}{arg.name.upper()}& {arg.name}')
                call_args.extend([f'{arg.name}.data()', f'{arg.name}.size()'])
                skip = True
            elif arg.type in [u'int', u'size_t', u'uint32_t', u'uint64_t',
                              u'int*', u'size_t*', u'uint32_t*', u'uint64_t*',
                              u'wally_map_verify_fn_t']:
                cpp_args.append(f'{arg.type} {arg.name}')
                call_args.append(f'{arg.name}')
            elif arg.is_pointer:
                if arg.is_pointer_pointer or n == num_args - 1:
                    cpp_args.append(f'{arg.type} {arg.name}')
                    call_args.append(f'{arg.name}')
                else:
                    t_types.append(f'class {arg.name.upper()}')
                    cpp_args.append(f'const {arg.name.upper()}& {arg.name}')
                    call_args.append(f'detail::get_p({arg.name})')
            else:
                assert False, f'Unmapped argument {func.name}:{arg.name}'

        impl = []
        if len(t_types):
            impl.append(f'template <{", ".join(t_types)}>')
        func_name = strip_wally_prefix(func.name)
        return_type = 'bool' if is_verify_function else 'int'
        impl.append(f'inline {return_type} {func_name}({", ".join(cpp_args)}) {{')
        if vardecl:
            impl.append(vardecl)
        impl.append(f'    int ret = ::{func.name}({", ".join(call_args)});')
        if vardecl:
            prev = func.args[-3]
            impl.append(f'    if (ret == WALLY_OK && n != static_cast<size_t>({prev.name}.size())) ret = WALLY_EINVAL;')
        if is_verify_function:
            impl.append(f'    return ret == WALLY_OK;')
        else:
            impl.append(f'    return detail::check_ret(__FUNCTION__, ret);')
        impl.extend([u'}', u''])
        (cpp_elements if func.is_elements else cpp)[func.name] = impl

    text = []
    for f in sorted(cpp.keys()):
        text.extend(cpp[f])
    text.append(u'#ifndef WALLY_ABI_NO_ELEMENTS')
    for f in sorted(cpp_elements.keys()):
        text.extend(cpp_elements[f])
    text[-1] = u'#endif // WALLY_ABI_NO_ELEMENTS'
    replace_text(u'include/wally.hpp', text,
                 [u'/* BEGIN AUTOGENERATED */', u'/* END AUTOGENERATED */'])


def gen_wasm_exports(funcs, all_funcs):
    funcs = sorted(filter(lambda f: f.name not in WASM_EXCLUDED_FUNCS, funcs))
    exports = ','.join([f"'_{func.name}' \\\n" for func in funcs if not func.is_elements])
    elements_exports = ','.join([f"'_{func.name}' \\\n" for func in funcs if func.is_elements])

    text = [
        f"EXPORTED_FUNCTIONS=\"['_malloc','_free',{exports}\"",
        'if [ -z "$DISABLE_ELEMENTS" ]; then',
        f'    EXPORTED_FUNCTIONS="$EXPORTED_FUNCTIONS"",{elements_exports}"',
        'fi',
        'EXPORTED_FUNCTIONS="$EXPORTED_FUNCTIONS""]"'
    ]
    replace_text(u'tools/wasm_exports.sh', text,
                 [u'# BEGIN AUTOGENERATED', u'# END AUTOGENERATED'])

def gen_wasm_package(funcs, all_funcs):
    # Simple single-argument types that can be identified without inspecting the next arguments
    # map of C type -> (JS type, TypeScript argument type, TypeScript return type)
    typemap_simple = {
        # Simple input primitive types
        'int'         : ('T.Int32', 'number', None),
        'size_t'      : ('T.Int32', 'number', None),
        'uint32_t'    : ('T.Int32', 'number', None),
        'uint64_t'    : ('T.Int64', 'bigint', None),

        'const char*' : ('T.String', 'string', None),

        # Single-argument output pointers
        'size_t*'   : ('T.DestPtr(T.Int32)', None, 'number'),
        'uint32_t*' : ('T.DestPtr(T.Int32)', None, 'number'),
        'uint64_t*' : ('T.DestPtr(T.Int64)', None, 'bigint'),
        'char**'    : ('T.DestPtrPtr(T.String)', None, 'string'),

        # These are only used once
        'char*' : ('T.OpaqueRef', 'Ref', None), # as the argument to `wally_free_string`
        'void*' : ('T.OpaqueRef', 'Ref', None), # as the argument to `wally_bzero`
        'wally_map_verify_fn_t' : ('T.OpaqueRef', 'Ref', None), # as the argument to `wally_map_init`
    }

    # Input arrays (represented as two arguments - the first identified by this map, followed by a FOO_len argument)
    # map of C type -> (JS type, TypeScript argument type)
    typemap_arrays = {
        'const unsigned char*' : ('T.Bytes', 'Buffer|Uint8Array'),
        'const uint32_t*'      : ('T.Uint32Array', 'Uint32Array|number[]'),
        'const uint64_t*'      : ('T.Uint64Array', 'BigUint64Array|Array<bigint>'),
    }

    # Output arrays
    # map of C type -> (JS type, TypeScript return type)
    typemap_output_arrays = {
        'char**': ('T.String', 'string'),
        'unsigned char*': ('T.Bytes', 'Buffer'),
        'uint32_t*': ('T.Uint32Array', 'Uint32Array'),
    }

    def map_args(func):
        num_args = len(func.args)
        next_index = 0
        js_args = []
        ts_args = []
        ts_returns = []

        while next_index < num_args:
            arg = func.args[next_index]
            curr_index = next_index
            next_index = next_index + 1

            # Input array types
            if is_array(func, arg, curr_index, num_args, typemap_arrays.keys()):
                (js_arg_type, ts_arg_type) = typemap_arrays[arg.type]
                js_args.append(js_arg_type)
                ts_args.append(f'{arg.name}: {ts_arg_type}')

                next_index = next_index + 1 # skip next 'FOO_len' argument
                continue

            # Input opaque reference
            if arg.is_struct and arg.is_pointer and not arg.is_pointer_pointer:
                # Sanity check to make sure we don't misidentify unrelated arguments
                assert arg.struct_name.startswith("wally_") or arg.struct_name == "ext_key" or arg.struct_name == "words"
                js_args.append('T.OpaqueRef')
                ts_args.append(f'{arg.name}: Ref_{arg.struct_name}')
                continue

            # Output pointer to an array
            if is_array(func, arg, curr_index, num_args, typemap_output_arrays.keys()):
                # Sanity check to make sure we don't misidentify unrelated arguments
                assert arg.name.endswith("_out") or arg.name in ('scalar', 'output')

                (array_type, ts_return_type) = typemap_output_arrays[arg.type]

                # Detect output buffer size (fixed or via a length utility function)
                len_arg = func.args[curr_index + 1]
                if func.name in MISSING_LEN_FUNCS:
                    len_fn = strip_wally_prefix(func.name) + '_len'
                    output_buffer_size = f'{len_fn}, {str(MISSING_LEN_FUNCS[func.name]).lower()}'
                elif len_arg.fixed_size:
                    output_buffer_size = f"C.{len_arg.fixed_size}"
                elif len_arg.max_size:
                    output_buffer_size = f"C.{len_arg.max_size}, true"
                elif func.buffer_len_fn:
                    len_fn = get_export_name(func.buffer_len_fn, all_funcs)
                    output_buffer_size = f"{len_fn}, {'true' if func.buffer_len_is_upper_bound else 'false'}"
                elif func.name in ('wally_scrypt', 'wally_descriptor_to_addresses'):
                    # User provides the intended output length as an argument to the JS API.
                    output_buffer_size = 'T.USER_PROVIDED_LEN'
                else:
                    assert False, f'ERROR: Unknown output array size for {func.name}:{arg.type}'

                # Variable-length buffers have an additional pointer for the number of bytes written/expected
                # See https://wally.readthedocs.io/en/latest/conventions/#variable-length-output-buffers
                if curr_index < num_args - 2 and func.args[curr_index + 2].type == 'size_t*' and func.args[curr_index + 2].name == 'written':
                    js_args.append(f'T.DestPtrVarLen({array_type}, {output_buffer_size})')
                    next_index = next_index + 2 # skip next two arguments: 'FOO_len' and 'written'

                # Fixed-sized output buffers
                else:
                    js_args.append(f'T.DestPtrSized({array_type}, {output_buffer_size})')
                    next_index = next_index + 1 # skip next 'FOO_len' argument

                if output_buffer_size == 'T.USER_PROVIDED_LEN':
                    ts_args.append('out_len: number')
                ts_returns.append(f'{arg.name}: {ts_return_type}')

                continue

            # Simple single-argument input/output types
            #
            # This must be checked after checking array output pointers (above), because a `uint32_t*` argument may
            # be either a uint32 or an array of uint32, depending on whether the following argument is a `_len` argument.
            if arg.type in typemap_simple:
                (js_arg_type, ts_arg_type, ts_return_type) = typemap_simple[arg.type]

                js_args.append(js_arg_type)

                if ts_arg_type:    ts_args.append(f'{arg.name}: {ts_arg_type}')
                if ts_return_type: ts_returns.append(f'{arg.name}: {ts_return_type}')

                continue

            # Output pointer to an opaque reference
            if arg.is_struct and arg.is_pointer and arg.is_pointer_pointer:
                # Sanity check to make sure we don't misidentify unrelated arguments
                assert arg.struct_name.startswith("wally_") or arg.struct_name == "ext_key" or arg.struct_name == "words"

                js_args.append('T.DestPtrPtr(T.OpaqueRef)')
                ts_returns.append(f'{arg.name}: Ref_{arg.struct_name}')
                continue

            assert False, f'ERROR: {func.name}: Unknown argument type "{arg.type}" {arg.name}'

        return (js_args, ts_args, ts_returns)

    # Drop excluded functions
    fn_included = filter(lambda f: f.name not in WASM_EXCLUDED_FUNCS, funcs)
    # Place functions that depend on the buffer length utility functions last, so that the utility
    # functions are available to them. Then sort by name.
    key_fn = lambda f: (f.buffer_len_fn is not None, get_export_name(f.name, all_funcs))
    fn_def_order = sorted(fn_included, key = key_fn)

    jscode = []
    tscode = []

    for func in fn_def_order:
        (js_args, ts_args, ts_returns) = map_args(func)
        fn_name = get_export_name(func.name, all_funcs)

        jscode.append(f"export const {fn_name} = wrap('{func.name}', [{', '.join(js_args)}]);")

        ts_return_code = 'void' if len(ts_returns) == 0 else f'{ts_returns[0].split(": ", 1)[1]}' if len(ts_returns) == 1 else f"[{', '.join(ts_returns)}]"
        tscode.append(f"export function {fn_name}({', '.join(ts_args)}): {ts_return_code};")

    # Inject generated functions into functions.js
    replace_text(u'src/wasm_package/src/functions.js', jscode,
                 [u'// BEGIN AUTOGENERATED', u'// END AUTOGENERATED'])

    # Inject generated TypeScript definitions into index.d.ts
    replace_text(u'src/wasm_package/src/index.d.ts', tscode,
                 [u'// BEGIN AUTOGENERATED', u'// END AUTOGENERATED'])


def get_function_defs(non_elements, internal_only):
     # Call sphinx to dump our definitions
    envs = {k:v for k,v in os.environ.items()}
    envs[u'WALLY_DOC_DUMP_FUNCS'] = u'1'
    if internal_only:
        envs[u'WALLY_DOC_DUMP_INTERNAL'] = u'1'
    cmd = ['sphinx-build', '-b', 'html', '-a', '-c', 'docs/source', 'docs/source', 'docs/build/html']
    process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=envs)

    # Process the lines into func objects for each function
    func_lines = process.stdout.decode('utf-8').split(u'\n')
    funcs = []
    for f in func_lines:
        if f.startswith(u'int '):
            funcs.append(Func(f, non_elements))
            add_meta = True
        elif f.startswith(u'* ') and add_meta:
            funcs[-1].add_metadata(f[2:])
        else:
            add_meta = False

    # Auto-detect output buffer length function based on the following naming conventions:
    # - funcname -> funcname_len / funcname_length / funcname_get_maximum_length
    # - funcname_to_bytes -> funcname_get_length
    # - funcname_to_bytes -> funcname_get_maximum_length
    # - _get_maximum_length implies is_upper_bound=true
    def is_len_fn(f):
        return f.endswith('_len') or f.endswith('_length')
    buffer_len_fns = set([f.name for f in funcs if is_len_fn(f.name)])
    for f in funcs:
        if f.name.endswith('_to_bytes'):
            possible_names = [ f.name[0:-9]+'_get_length', f.name[0:-9]+'_get_maximum_length' ]
        else:
            possible_names = [ f.name + '_len', f.name + '_length', f.name + '_get_maximum_length' ]

        for name in possible_names:
            if name in buffer_len_fns:
                f.buffer_len_fn = name
                f.buffer_len_is_upper_bound = name.endswith('_maximum_length')
                break

    return funcs


def list_header_files():
    result = subprocess.run(['ls', 'include'], capture_output=True, text=True, check=True)
    all_files = result.stdout.strip().split('\n')
    header_files = [file for file in all_files if file.endswith('.h')]
    return header_files

def gen_wamr_bindings(funcs, all_funcs):
    func_dict = {f.name: f for f in funcs}

    output = []

    output.append('/* GENERATED FILE DO NOT EDIT */')
    output.append('')
    output.append('#include <wasm_export.h>')
    output.append('#include <string.h>')

    for header_fname in list_header_files():
        output.append(f'#include <{header_fname}>')

    output.append('/* do not reorder this */')
    output.append('#include <bip32_int.h>')
    output.append('')

    for func_name in func_dict:
        if func_name == 'wally_set_operations':
            continue
        func = func_dict.get(func_name)
        wrapper_code = generate_wamr_wrapper(func)
        output.extend(wrapper_code)
        output.append('')

    output.append('static const NativeSymbol wns[] = {')
    for func_name in func_dict:
        if func_name == 'wally_set_operations':
            continue
        func = func_dict.get(func_name)
        sig = generate_wamr_signature(func)
        output.append(f'    EXPORT_WASM_API_WITH_SIG2({func.name}, "{sig}"),')
    output.append('};')
    output.append('')
    output.append('const NativeSymbol* get_wally_bindings(void) { return wns; }')
    output.append('size_t get_wally_bindings_len(void) { return sizeof(wns) / sizeof(NativeSymbol); }')

    # FIXME: change the output directory to whatever the rest of the script does I suppose
    with open('/tmp/wally_bindings.c', 'w') as f:
        f.write('\n'.join(output))

def generate_wamr_wrapper(func):
    code = []
    func_name = func.name + '_wrapper'

    # first argument is wasm_exec_env_t exec_env
    args = func.args

    # build wrapper arguments
    wrapper_args = ['wasm_exec_env_t exec_env']
    for arg in args:
        if arg.name == 'exec_env':
            continue  # Exclude exec_env
        wrapper_args.append(f'{arg.type} {arg.name}')

    # build function signature
    code.append(f'static int {func_name}(')
    code.append('    ' + ', '.join(wrapper_args) + ')')
    code.append('{')

    map_pptr_return_value =  args[-1].is_pointer_pointer and not (args[-1].is_struct and args[-1].is_opaque)
    if map_pptr_return_value or any(arg.is_pointer for arg in args):
        code.append(f'    wasm_module_inst_t wasm_module_inst = wasm_runtime_get_module_inst(exec_env);')

    # map input NULL pointers to native NULL - ie. do not treat as offset
    for arg in args:
        if arg.is_pointer or arg.type.strip() == 'wally_map_verify_fn_t':
            code.append(f'    if (!wasm_runtime_addr_native_to_app(wasm_module_inst, (void*){arg.name})) {{')
            code.append(f'        {arg.name} = NULL;')
            code.append(f'    }}')

            if arg.type.strip() == 'wally_map_verify_fn_t':
                code.append(f'    if ({arg.name}) {{')
                code.append(f'        return WALLY_EINVAL;')
                code.append(f'    }}')

    # explicitly map return value if required
    # note output NULLs are left as NULL and not mapped
    if map_pptr_return_value:
        call_args = [arg.name for arg in func.args]
        code.append(f'    if (!{args[-1].name}) {{')
        code.append(f'        return WALLY_EINVAL;')
        code.append(f'    }}')
        code.append(f'')
        code.append(f'    {arg.type.strip()[:-1]} wamr_result = NULL;')
        code.append(f'    const int wwres = {func.name}({", ".join(call_args[:-1] + ["&wamr_result"])});')
        code.append(f'    if (wwres != WALLY_OK) {{')
        code.append(f'        return wwres;')
        code.append(f'    }}')
        code.append(f'    uint32_t wamr_index_gen = 0;')
        code.append(f'    if (wamr_result) {{');
        code.append(f'        wamr_index_gen = wasm_runtime_addr_native_to_app(wasm_module_inst, (void*)wamr_result);')
        code.append(f'        if (!wamr_index_gen) {{')
        code.append(f'            return WALLY_ERROR;')
        code.append(f'        }}')
        code.append(f'    }}')
        code.append(f'    *{args[-1].name} = ({arg.type.strip()[:-1]})(uintptr_t)wamr_index_gen;')
        code.append(f'    return wwres;')
    else:
        call_args = [arg.name for arg in func.args]
        code.append(f'    return {func.name}({", ".join(call_args)});')

    code.append('}')
    return code

def generate_wamr_signature(func):
    param_letters = []
    args_list = func.args
    arg_index = 0

    while arg_index < len(args_list):
        arg = args_list[arg_index]
        arg_type = arg.type.strip()

        if arg_type in ['int', 'size_t', 'uint32_t']:
            param_letters.append('i')
        elif arg_type == 'uint64_t':
            param_letters.append('I')
        elif arg_type in ['const char*', 'char*']:
            param_letters.append('$')
        elif arg.is_pointer_pointer:
            param_letters.append('*')
        elif arg.is_pointer:
            # check if next arg is length parameter
            # FIXME: maybe there is a better way to check this
            if (arg_index + 1 < len(args_list) and
                args_list[arg_index + 1].type.strip() in ['size_t', 'uint32_t'] and
                args_list[arg_index + 1].name.endswith(('_len', '_length', 'len'))):
                param_letters.append('*')
                param_letters.append('~')
                arg_index += 1  # skip length parameter
            else:
                # FIXME: let's try some types from here
                if arg.is_struct and arg.is_opaque:
                    #param_letters.append('r')  # FIXME
                    param_letters.append('i')
                else:
                    param_letters.append('*')
        else:
            # FIXME: let's try some types from here
            if arg.is_struct and arg.is_opaque:
                #param_letters.append('r')  # FIXME
                param_letters.append('i')
            else:
                param_letters.append('*')


        arg_index += 1

    return_type_letter = 'i'  # assuming all functions return 'int'
    signature = '(' + ''.join(param_letters) + ')' + return_type_letter
    return signature

def generate_wasm_noemscripten_wrapper(func):
    code = []

    args = func.args

    wrapper_args = []
    for arg in args:
        wrapper_args.append(f'{arg.name}')

    # build function signature
    code.append(f'    function {func.name}(')
    code.append('        ' + ', '.join(wrapper_args) + ')')
    code.append('    {')
    # what do we need to do here:
    # 1 - we received 'written' which is an index into the callers memory
    # 2 - the caller memory is not accessible to this wally because it is running in a different instance
    # 3 - they can share the heap but that's not helping much because if something pointing to the stack is passed things break
    # 4 - we can have the function be passed in the memory instance
    code.append(f'''        const otherWasmInstance = get_other_wasm_instance();
        const other_common_imports = get_other_wasm_common();
        const memoryViewWally = new DataView(wallyWasmInstance.exports.memory.buffer);
        const memoryView = new DataView(otherWasmInstance.exports.memory.buffer);
    ''')

    params = []

    #function wally_hex_from_bytes(
    #    bytes, bytes_len, output)
    # so first thing we need to do is allocate a buffer of next arg value

    # so if the parameter is a pointer but is not to a char

    # for each argument that is a pointer
    skip = False

    #         // WALLY_CORE_API int wally_tx_get_version(const struct wally_tx *tx_in, size_t *written);


    for index, arg in enumerate(args):
        if skip:
            skip = False
            continue

        #print(arg.type)
        # so here we can check if the next is like a len then we are golden sort of
        if not arg.is_pointer and not arg.is_pointer_pointer or (len(args) == 1 and arg.type == 'char*') or (arg.is_struct and (arg.is_const or len(args) == 1)):
            params.append(f'{arg.name}')
        elif (arg.is_pointer or arg.is_pointer_pointer):
            # say it is not a char but we should check and we assume the next thing
            if index + 1 < len(args) and (not args[index + 1].is_pointer) and args[index+1].type in ['size_t']:
                # so here we consume next too
                code.append(f'''
        const ptr_{arg.name} = common_imports.env.malloc({args[index + 1].name});
        for (let i = 0; i < {args[index + 1].name}; ++i) {{
            const tmp = memoryView.getUint8({arg.name} + i, true);
            memoryViewWally.setUint8(ptr_{arg.name} + i, tmp, true);
        }}''')
                skip = True
                params.append(f'ptr_{arg.name}')
                params.append(f'{args[index + 1].name}')
            elif arg.type == 'const char*':
                # we need to copy the string over but we need to calculate the size first
                # we can't call common_imports because the alue is in other wasm
                # so for now we reimplement it?
                code.append(f'''
        let length_{arg.name} = 0;
        while (memoryView.getUint8({arg.name} + length_{arg.name}) !== 0) {{
            ++length_{arg.name};
        }}
        const ptr_{arg.name} = common_imports.env.malloc(length_{arg.name} + 1);

        for (let i = 0; i < length_{arg.name}; ++i) {{
            const tmp = memoryView.getUint8({arg.name} + i, true);
            memoryViewWally.setUint8(ptr_{arg.name} + i, tmp, true);
        }}
        memoryViewWally.setUint8(ptr_{arg.name} + length_{arg.name}, 0, true);
        ''')
                params.append(f'ptr_{arg.name}')
            else:
                code.append(f'''
        const ptr_{arg.name} = common_imports.env.malloc(4);
        const {arg.name}_original_value = memoryView.getUint32({arg.name}, true);
        memoryViewWally.setUint32(ptr_{arg.name}, {arg.name}_original_value, true);
                ''')

                params.append(f'ptr_{arg.name}')
        else:
            print("Other @@@@@@@@@@@@ arg", arg.type, arg.name)

    # FIXME: should do all params
    # the actual call with payload
    code.append(f'''
        const result = wallyWasmInstance.exports.{func.name}({", ".join(params)});
    ''')

    for index, arg in enumerate(args):
        if not arg.is_pointer and not arg.is_pointer_pointer or (len(args) == 1 and arg.type == 'char*') or (arg.is_struct and (arg.is_const or len(args) == 1)):
            print("Other arz", arg.type, arg.name)
            pass
        elif arg.is_pointer or arg.is_pointer_pointer:
            if (not arg.is_const) and index + 1 < len(args) and (not args[index + 1].is_pointer) and args[index+1].type in ['size_t']:
                code.append(f'''
        for (let i = 0; i < {args[index + 1].name}; ++i) {{
            const tmp = memoryViewWally.getUint8(ptr_{arg.name} + i, true);
            memoryView.setUint8({arg.name} + i, tmp, true);
        }}
        common_imports.env.free(ptr_{arg.name});
            ''')
            elif arg.is_const:
                code.append(f'''
        common_imports.env.free(ptr_{arg.name});
            ''')
            elif arg.type == 'char**':
                # so in this case wally create a string into the buffer we provided ptr_{arg.name}
                # it seems we then need to allocate again after
                # 1 count how many
                # 2 malloc in the right thing - bingo we are fucked we need malloc from the companion or to share the heap
                # 2 a - if we assumed we shared the heap then this would be it more or less maybe we can share the exit with other things
                # 2 b - if we do not share the heap now we need to do the magic translation of heap mallocs
                # in this case we need to call wally_free_string and copy all the data - sigh
                code.append(f'''
        const ptr_{arg.name}_data = memoryViewWally.getUint32(ptr_{arg.name}, true);
        // first we need to size the returned string
        let new_length_{arg.name} = 0;
        while (memoryViewWally.getUint8(ptr_{arg.name}_data + new_length_{arg.name}) !== 0) {{
            ++new_length_{arg.name};
        }}
        // then we need to malloc like that
        const new_{arg.name} = other_common_imports.env.malloc(new_length_{arg.name} + 1);
        // now we need to copy the string
        for (let i = 0; i < new_length_{arg.name}; ++i) {{
            const tmp = memoryViewWally.getUint8(ptr_{arg.name}_data + i, true);
            memoryView.setUint8(new_{arg.name} + i, tmp, true);
        }}
        memoryView.setUint8(new_{arg.name} + new_length_{arg.name}, 0, true);
        // now we need to free wally
        // then we need to copy this pointer into {arg.name} with setUint32
        memoryView.setUint32({arg.name}, new_{arg.name}, true);
        common_imports.env.free(ptr_{arg.name});
        wallyWasmInstance.exports.wally_free_string(ptr_output_data);
            ''')
            else:
                code.append(f'''
        const {arg.name}_actual_value = memoryViewWally.getUint32(ptr_{arg.name}, true);
        memoryView.setUint32({arg.name}, {arg.name}_actual_value, true);
        common_imports.env.free(ptr_{arg.name});
            ''')
        else:
            assert False
            print("Other @@@@ arz", arg.type, arg.name)
            pass
    code.append(f'''
        return result;
    ''')
    code.append('    }')
    return code


wasm_loader = '''

async function wally_setup(get_other_wasm_instance, get_other_wasm_common) {
    let wallyWasmInstance;
    let wally_memory = new WebAssembly.Memory({
        initial : 64,
        maximum : 256
    });
    function get_memory_buffer() {
        return wallyWasmInstance.exports.memory.buffer;
    }
    const [init_heap, common_imports] = get_common_imports(wally_memory, get_memory_buffer);

    const wallyWasmModule = await WebAssembly.instantiateStreaming(fetch('wallypure.wasm'), common_imports);
    wallyWasmInstance = wallyWasmModule.instance;
    init_heap(wallyWasmInstance);
'''

ad_hoc_functions = '''
    function wally_free_string(str)
    {
        const otherWasmInstance = get_other_wasm_instance();
        const memoryView = new DataView(otherWasmInstance.exports.memory.buffer);
        const other_common_imports = get_other_wasm_common();

        let str_len = 0;
        while (memoryView.getUint8(str + str_len !== 0)) {
            ++str_len;
        }

        if (str_len) {
            other_common_imports.env.memset(str, 0, str_len);
        }
        other_common_imports.env.free(str);

        return WALLY_OK;
    }

    function wally_bzero(bytes, bytes_len)
    {
        const other_common_imports = get_other_wasm_common();
        other_common_imports.env.memset(bytes, 0, bytes_len);
        return WALLY_OK;
    }
'''

def gen_wasm_noemscripten_bindings(funcs, all_funcs):
    func_dict = {f.name: f for f in funcs}

    output = []

    output.append('/* GENERATED FILE DO NOT EDIT */')
    output.append('')
    output.append('const WALLY_OK = 0;')
    output.append(wasm_loader)

    exclude_funcs = ['wally_free_string', 'wally_bzero']

    for func_name in func_dict:
        if func_name in exclude_funcs:
            continue
        func = func_dict.get(func_name)
        wrapper_code = generate_wasm_noemscripten_wrapper(func)
        output.extend(wrapper_code)
        output.append('')

    output.append(ad_hoc_functions)

    output.append('    return {')
    output.append('        env : {')
    for func_name in func_dict:
        output.append(f'            {func_name},')
    output.append('        },')
    output.append('    };')
    output.append('}')

    with open('/tmp/wally_bindings.js', 'w') as f:
        f.write('\n'.join(output))

if __name__ == "__main__":
    non_elements = get_non_elements_functions()

    external_funcs = get_function_defs(non_elements, False)
    internal_funcs = get_function_defs(non_elements, True)

    all_funcs = external_funcs + internal_funcs
    all_names = set([f.name for f in all_funcs])

    # Generate the wrapper code
    #gen_python_cffi(external_funcs, all_names, False)
    #gen_python_cffi(internal_funcs, all_names, True)

    #gen_python_swig(all_funcs, all_names)
    #gen_java_swig(external_funcs, all_names)
    #gen_wally_hpp(external_funcs, all_names)

    #gen_wasm_exports(all_funcs, all_names)
    #gen_wasm_package(all_funcs, all_names)

    gen_wamr_bindings(all_funcs, all_names)
    gen_wasm_noemscripten_bindings(all_funcs, all_names)
