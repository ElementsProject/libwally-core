#!/usr/bin/env python3
import os
import subprocess
import sys

# Structs with no definition in the public header files
OPAQUE_STRUCTS = [u'words']


def replace_text(filename, text, delims):
    lines = [line.rstrip() for line in open(filename)]
    start, end = lines.index(delims[0]), lines.index(delims[1])
    replaced = lines[:start + 1] + text + lines[end:]
    replaced = [l + u'\n' for l in replaced]
    open(filename, u'w').writelines([l for l in replaced])

def get_non_elements_functions():
    # SWIG_PYTHON_BUILD=1 used to include internal functions too
    cmd = "-E -DSWIG_PYTHON_BUILD=1 include/*.h src/bip32_int.h src/transaction_int.h |" \
          "sort | uniq | sed 's/^ *WALLY_CORE_API//' | grep '^ *int ' | grep '(' | sed -e 's/^ *int //g' -e 's/(.*//g' | egrep '^wally_|^bip'"
    try:
        funcs = subprocess.check_output(u'gcc ' + cmd, shell=True)
    except subprocess.CalledProcessError:
        funcs = subprocess.check_output(u'clang ' + cmd, shell=True)
    return funcs.decode('utf-8').split(u'\n')


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
            assert False, 'Unknown metadata format {}'.format(m)

class Func(object):
    def __init__(self, definition, non_elements):
        # Strip return type and closing ')', extract name
        self.name, definition = definition[4:-1].split(u'(')
        # Parse arguments
        self.args = [Arg(d) for d in definition.split(u', ')]
        self.is_elements = self.name not in non_elements
        self.buffer_len_fn = None
        self.buffer_len_is_upper_bound = None

    def __lt__(self, other):
        return self.name < other.name

    def add_metadata(self, m):
        arg_name = m.split('(')[1].split(',')[0].strip()
        args = [arg for arg in self.args if arg.name == arg_name]
        assert len(args) == 1, 'invalid metadata reference {}'.format(m)
        args[0].add_metadata(m)

def is_array(func, arg, n, num_args, types):
    return arg.type in types and n != num_args -1 and \
               func.args[n + 1].type == u'size_t' and \
               func.args[n + 1].name.endswith(u'len')


def is_buffer(func, arg, n, num_args):
    return is_array(func, arg, n, num_args, [u'const unsigned char*', u'unsigned char*'])


def is_int_buffer(func, arg, n, num_args):
    return is_array(func, arg, n, num_args, [u'const uint32_t*', u'const uint64_t*'])


def gen_python_cffi(funcs, internal_only):
    typemap = {
        u'int'           : u'c_int',
        u'size_t*'       : u'c_size_t_p',
        u'size_t'        : u'c_size_t',
        u'uint32_t*'     : u'c_uint_p',
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
        if argtype == u'uint64_t*' and n != num_args - 1:
            return u'POINTER(c_uint64)'
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


def gen_python_swig(funcs):
    def map_arg(func, arg, n, num_args):
        if is_buffer(func, arg, n, num_args):
            macro = u'output' if arg.type == u'unsigned char*' else u'nullable'
            return f'%pybuffer_{macro}_binary({arg.type} {arg.name}, size_t {func.args[n + 1].name});'
        return u''

    swig = []
    for func in funcs:
        num_args = len(func.args)
        mapped = [map_arg(func, arg, i, num_args) for i, arg in enumerate(func.args)]
        swig.extend([m for m in mapped if m])

    swig = sorted(set(swig))
    replace_text(u'src/swig_python/swig.i', swig,
                 [u'/* BEGIN AUTOGENERATED */', u'/* END AUTOGENERATED */'])


def gen_java_swig(funcs):
    def map_arg(func, arg, n, num_args):
        if arg.type in [u'const unsigned char*', u'unsigned char*'] and \
                n != num_args -1 and func.args[n + 1].type == u'size_t' and \
                func.args[n + 1].name.endswith(u'len'):
            return f'%apply(char *STRING, size_t LENGTH) {{ ({arg.type} {arg.name}, size_t {func.args[n + 1].name}) }};'
        return u''

    swig = []
    for func in funcs:
        num_args = len(func.args)
        mapped = [map_arg(func, arg, i, num_args) for i, arg in enumerate(func.args)]
        swig.extend([m for m in mapped if m])

    swig = sorted(set(swig))
    replace_text(u'src/swig_java/swig.i', swig,
                 [u'/* BEGIN AUTOGENERATED */', u'/* END AUTOGENERATED */'])


def gen_wally_hpp(funcs):
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
            if is_buffer(func, arg, n, num_args) or is_int_buffer(func, arg, n, num_args):
                t_types.append(f'class {arg.name.upper()}')
                const = u'const ' if arg.is_const else ''
                cpp_args.append(f'{const}{arg.name.upper()}& {arg.name}')
                call_args.extend([f'{arg.name}.data()', f'{arg.name}.size()'])
                skip = True
            elif arg.type == u'size_t*' and arg.name == u'written' and \
                    n >= 2 and is_buffer(func, func.args[n-2], n-2, num_args):
                vardecl = u'    size_t n;'
                cpp_args.append(f'{arg.type} {arg.name} = 0')
                call_args.append(f'{arg.name} ? {arg.name} : &n')
            elif arg.type in [u'int', u'size_t', u'uint32_t', u'uint64_t',
                              u'int*', u'size_t*', u'uint32_t*', u'uint64_t*']:
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

        impl = []
        if len(t_types):
            impl.append(f'template <{", ".join(t_types)}>')
        func_name = func.name[6:] if func.name.startswith(u'wally_') else func.name
        impl.append(f'inline int {func_name}({", ".join(cpp_args)}) {{')
        if vardecl:
            impl.append(vardecl)
        impl.append(f'    int ret = ::{func.name}({", ".join(call_args)});')
        if vardecl:
            prev = func.args[-3]
            impl.append(f'    return written || ret != WALLY_OK ? ret : n == static_cast<size_t>({prev.name}.size()) ? WALLY_OK : WALLY_EINVAL;')
        else:
            impl.append(f'    return ret;')
        impl.extend([u'}', u''])
        # FIXME: sort
        (cpp_elements if func.is_elements else cpp)[func.name] = impl

    text = []
    for f in sorted(cpp.keys()):
        text.extend(cpp[f])
    text.append(u'#ifdef BUILD_ELEMENTS')
    for f in sorted(cpp_elements.keys()):
        text.extend(cpp_elements[f])
    text[-1] = u'#endif // BUILD_ELEMENTS'
    replace_text(u'include/wally.hpp', text,
                 [u'/* BEGIN AUTOGENERATED */', u'/* END AUTOGENERATED */'])


def gen_wasm_exports(funcs):
    funcs = sorted(funcs)
    exports = ','.join([f"'_{func.name}' \\\n" for func in funcs if not func.is_elements])
    elements_exports = ','.join([f"'_{func.name}' \\\n" for func in funcs if func.is_elements])

    text = [
        f"EXPORTED_FUNCTIONS=\"['_malloc','_free',{exports}\"",
        'if [ -n "$ENABLE_ELEMENTS" ]; then',
        f'    EXPORTED_FUNCTIONS="$EXPORTED_FUNCTIONS"",{elements_exports}"',
        'fi',
        'EXPORTED_FUNCTIONS="$EXPORTED_FUNCTIONS""]"'
    ]
    replace_text(u'tools/wasm_exports.sh', text,
                 [u'# BEGIN AUTOGENERATED', u'# END AUTOGENERATED'])

def gen_wasm_package(funcs):

    # Simple single-argument types that can be identified without inspecting the next arguments
    typemap_simple = {
        # Simple primitive types
        'int'         : 'T.Int32',
        'size_t'      : 'T.Int32',
        'uint32_t'    : 'T.Int32',
        'uint64_t'    : 'T.Int64',

        'const char*' : 'T.String',

        # Single-argument pointers
        'size_t*'   : 'T.DestPtr(T.Int32)',
        'uint32_t*' : 'T.DestPtr(T.Int32)',
        'uint64_t*' : 'T.DestPtr(T.Int64)',
        'char**'    : 'T.DestPtrPtr(T.String)',

        # These are only used once
        'char*' : 'T.OpaqueRef', # as the argument to `wally_free_string`
        'void*' : 'T.OpaqueRef', # as the argument to `wally_bzero`
        'wally_map_verify_fn_t' : 'T.OpaqueRef', # as the argument to `wally_map_init`
    }

    # Input arrays (represented as two arguments - the first identified by this map, followed by a FOO_len argument)
    typemap_arrays = {
         'const unsigned char*' : 'T.Bytes',
         'const uint32_t*'      : 'T.Uint32Array',
         'const uint64_t*'      : 'T.Uint64Array',
    }

    # Output arrays
    typemap_output_arrays = {
        'unsigned char*': 'T.Bytes',
        'uint32_t*': 'T.Uint32Array',
    }

    # Output buffer length functions implemented on the JS side
    js_buffer_size_fns = {
        'wally_hex_to_bytes': 'hex_to_bytes_len, false',
        'wally_hex_n_to_bytes': 'hex_n_to_bytes_len, false',
        'wally_aes': 'aes_len, false',
        'wally_aes_cbc': 'aes_cbc_len, true', # is_upper_bound=true only needed for the case of decryption
        'wally_ec_sig_from_bytes': 'ec_sig_from_bytes_len, false',
        'wally_format_bitcoin_message': 'format_bitcoin_message_len, true',
        'wally_script_push_from_bytes': 'script_push_from_bytes_len, true',
        'wally_scriptpubkey_multisig_from_bytes': 'scriptpubkey_multisig_from_bytes_len, true',
        'wally_scriptsig_multisig_from_bytes': 'scriptsig_multisig_from_bytes_len, true',
        'wally_wif_to_public_key': 'wif_to_public_key_len, true',
        'wally_scriptpubkey_csv_2of2_then_1_from_bytes': 'scriptpubkey_csv_2of2_then_1_from_bytes_len, true',
        'wally_scriptpubkey_csv_2of2_then_1_from_bytes_opt': 'scriptpubkey_csv_2of2_then_1_from_bytes_opt_len, true',
        'wally_scriptpubkey_csv_2of3_then_2_from_bytes': 'scriptpubkey_csv_2of3_then_2_from_bytes_len, true',

        'wally_asset_surjectionproof': 'asset_surjectionproof_len, true',
        'wally_asset_pak_whitelistproof': 'asset_pak_whitelistproof_len, false',
        'wally_elements_pegout_script_from_bytes': 'elements_pegout_script_from_bytes_len, true',
        'wally_elements_pegin_contract_script_from_bytes': 'elements_pegin_contract_script_from_bytes_len, true',
    }

    def map_args(func):
        num_args = len(func.args)
        next_index = 0
        js_args = []

        while next_index < num_args:
            arg = func.args[next_index]
            curr_index = next_index
            next_index = next_index + 1

            # Input array types
            if is_array(func, arg, curr_index, num_args, typemap_arrays.keys()):
                js_args.append(typemap_arrays[arg.type])
                next_index = next_index + 1 # skip next 'FOO_len' argument
                continue

            # Input opaque reference
            if arg.is_struct and arg.is_pointer and not arg.is_pointer_pointer:
                # Sanity check to make sure we don't misidentify unrelated arguments
                assert arg.struct_name.startswith("wally_") or arg.struct_name == "ext_key" or arg.struct_name == "words"
                js_args.append('T.OpaqueRef')
                continue

            # Output pointer to an array
            if is_array(func, arg, curr_index, num_args, typemap_output_arrays.keys()):
                # Sanity check to make sure we don't misidentify unrelated arguments
                assert arg.name.endswith("_out") or arg.name == 'scalar'

                # Get the inner array data type
                array_type = typemap_output_arrays[arg.type]

                # Detect output buffer size (fixed or via a length utility function)
                len_arg = func.args[curr_index + 1]
                if len_arg.fixed_size:
                    output_buffer_size = f"C.{len_arg.fixed_size}"
                elif len_arg.max_size:
                    output_buffer_size = f"C.{len_arg.max_size}, true"
                elif func.buffer_len_fn:
                    output_buffer_size = f"{export_name(func.buffer_len_fn)}, {'true' if func.buffer_len_is_upper_bound else 'false'}"
                elif func.name in js_buffer_size_fns:
                    output_buffer_size = js_buffer_size_fns[func.name]
                else:
                    # XXX Use a default fallback value for now, until all length functions are handled
                    print(f"MISSING output buffer size for {func.name}:{arg.name}")
                    output_buffer_size = 100

                # Variable-length buffers have an additional pointer for the number of bytes written/expected
                # See https://wally.readthedocs.io/en/latest/conventions/#variable-length-output-buffers
                if curr_index < num_args - 2 and func.args[curr_index + 2].type == 'size_t*' and func.args[curr_index + 2].name == 'written':
                    js_args.append(f'T.DestPtrVarLen({array_type}, {output_buffer_size})')
                    next_index = next_index + 2 # skip next two arguments: 'FOO_len' and 'written'

                # Fixed-sized output buffers
                else:
                    js_args.append(f'T.DestPtrSized({array_type}, {output_buffer_size})')
                    next_index = next_index + 1 # skip next 'FOO_len' argument

                continue

            # Simple single-argument input/output types
            #
            # This must be checked after checking array output pointers (above), because a `uint32_t*` argument may
            # be either a uint32 or an array of uint32, depending on whether the following argument is a `_len` argument.
            if arg.type in typemap_simple:
                js_args.append(typemap_simple[arg.type])
                continue

            # Output pointer to an opaque reference
            if arg.is_struct and arg.is_pointer and arg.is_pointer_pointer:
                # Sanity check to make sure we don't misidentify unrelated arguments
                assert arg.struct_name.startswith("wally_") or arg.struct_name == "ext_key" or arg.struct_name == "words"

                js_args.append('T.DestPtrPtr(T.OpaqueRef)')
                continue

            assert False, f'ERROR: Unknown argument type "{arg.type}"'

        return js_args

    func_names = set([ func.name for func in funcs ])

    def export_name(func_name):

        # Strip the '_alloc' suffix (this is typically what the user wants)
        if func_name.endswith("_alloc"):
            func_name = func_name[0:-6]
        # Add '_noalloc' suffix to the non-alloc variation (should be used rarely)
        elif f"{func_name}_alloc" in func_names:
            func_name = f"{func_name}_noalloc"

        # Strip 'wally_' prefix to keep things DRY (everything is already namespaced under the package)
        if func_name.startswith('wally_'):
            func_name = func_name[6:]

        return func_name

    # Place functions that depend on the buffer length utility functions last, so that the utility
    # functions are available to them. Then sort by name.
    fn_def_order = sorted(funcs, key = lambda f: (f.buffer_len_fn is not None, export_name(f.name)))

    jscode = [
        f"export const {export_name(func.name)} = wrap('{func.name}', [{', '.join(map_args(func))}]);"
        for func in fn_def_order
    ]

    # Inject generated functions into functions.js
    replace_text(u'src/wasm_package/functions.js', jscode,
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
        elif f.startswith(u'FIXED_SIZED_OUTPUT(') or f.startswith(u'MAX_SIZED_OUTPUT('):
            funcs[-1].add_metadata(f)

    # Auto-detect output buffer length function based on the following naming conventions:
    # - funcname -> funcname_len / funcname_length
    # - funcname_to_bytes -> funcname_get_length
    # - funcname_to_bytes -> funcname_get_maximum_length (implies is_upper_bound=true)
    buffer_len_fns = set([f.name for f in funcs if f.name.endswith('_len') or f.name.endswith('_length')])
    for f in funcs:
        if f.name.endswith('_to_bytes'):
            possible_names = [ f.name[0:-9]+'_get_length', f.name[0:-9]+'_get_maximum_length' ]
        else:
            possible_names = [ f.name + '_len', f.name + '_length' ]

        for name in possible_names:
            if name in buffer_len_fns:
                f.buffer_len_fn = name
                f.buffer_len_is_upper_bound = name.endswith('_maximum_length')
                break

    return funcs

if __name__ == "__main__":
    non_elements = get_non_elements_functions()

    external_funcs = get_function_defs(non_elements, False)
    internal_funcs = get_function_defs(non_elements, True)
    all_funcs = external_funcs + internal_funcs

    # Generate the wrapper code
    gen_python_cffi(external_funcs, False)
    gen_python_cffi(internal_funcs, True)

    gen_python_swig(external_funcs)
    gen_java_swig(external_funcs)
    gen_wally_hpp(external_funcs)

    gen_wasm_exports(all_funcs)
    gen_wasm_package(all_funcs)