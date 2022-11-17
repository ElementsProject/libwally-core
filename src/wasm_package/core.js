import assert from 'assert'
import InitWallyModule from './libwally_wasm/wallycore.cjs'
import { WALLY_OK, WALLY_ERROR, WALLY_EINVAL, WALLY_ENOMEM } from './const.js'

// Initialize the underlying WASM module and expose it publicly
const Module = await InitWallyModule()
export const WasmModule = Module

//
// Types
//

export const types = {}

// Number types
types.Number = (llvm_ir_type, size) => ({
    wasm_type: 'number',
    to_wasm: num => ({ args: [num] }),

    read_ptr: ptr => Module.getValue(ptr, llvm_ir_type),
    free_ptr: ptr => Module._free(ptr),
    malloc: _ => Module._malloc(size),
})
// Currently only Int32 and Int64 are needed for libwally, but its easy enough to
// make the others available too in case they're needed later.
types.Int8 = types.Number('i8', 1)
types.Int16 = types.Number('i16', 2)
types.Int32 = types.Number('i32', 4)
types.Int64 = types.Number('i64', 8)
types.Float = types.Number('float', 4)
types.Double = types.Number('double', 8)

// UTF-8 null-terminated string
types.String = {
    wasm_type: 'string',
    to_wasm: str => ({ args: [str] }),

    read_ptr: ptr => Module.UTF8ToString(ptr),
    free_ptr: ptr => assert(_wally_free_string(ptr) == WALLY_OK),
}
const _wally_free_string = Module.cwrap('wally_free_string', 'number', ['number'])

// Array of integers. Used for byte buffers and 32/64 bits numbers.
// Passed to C as two arguments, the pointer and the array length.
// Represented in JS as the IntArrayType, which is a Uint{8,32,64}Array.
types.IntArray = (IntArrayType, heap) => ({
    wasm_types: ['number', 'number'],
    to_wasm: int_arr => {
        if (!Array.isArray(int_arr) && !(int_arr instanceof IntArrayType)) {
            throw new WallyArrayNumTypeError(int_arr, IntArrayType)
        }

        var arr_ptr = Module._malloc(int_arr.length * IntArrayType.BYTES_PER_ELEMENT);
        heap.set(int_arr, arr_ptr / IntArrayType.BYTES_PER_ELEMENT)

        return {
            args: [arr_ptr, int_arr.length],
            cleanup: _ => Module._free(arr_ptr)
        }
    },

    malloc_sized: array_size => Module._malloc(array_size * IntArrayType.BYTES_PER_ELEMENT),

    read_ptr_sized: (ptr, array_size) => {
        const heap_offset = ptr / IntArrayType.BYTES_PER_ELEMENT
        return new IntArrayType(heap.subarray(heap_offset, heap_offset + array_size))
    },

    free_ptr: ptr => Module._free(ptr),
})

types.Bytes = types.IntArray(Uint8Array, Module.HEAPU8)
types.Uint32Array = types.IntArray(Uint32Array, Module.HEAPU32)
types.Uint64Array = types.IntArray(BigUint64Array, Module.HEAPU64)

// An opaque reference returned via DestPtrPtr that can be handed back to libwally
types.OpaqueRef = {
    wasm_type: 'number',
    to_wasm: ptr => ({ args: [ptr] }),

    read_ptr: ptr => ptr,
    free_ptr: _ptr => {
        // noop. the opaque reference is returned as-is and needs to be freed
        // manually using the specialized wally_free_* function.
    },
}


// A destination pointer to a primitive fixed-size number data type
types.DestPtr = type => ({
    no_user_args: true,
    wasm_type: 'number',
    to_wasm: _ => {
        const dest_ptr = type.malloc()
        return {
            args: [dest_ptr],
            return: _ => type.read_ptr(dest_ptr),
            cleanup: _ => type.free_ptr(dest_ptr),
        }
    }
})

// A destination pointer-of-pointer to the inner `type` (String or OpaqueRef)
types.DestPtrPtr = type => ({
    no_user_args: true,
    wasm_type: 'number',
    to_wasm: _ => {
        const dest_ptrptr = Module._malloc(4)
        return {
            args: [dest_ptrptr],
            return: _ => {
                const dest_ptr = Module.getValue(dest_ptrptr, '*')
                    , js_value = type.read_ptr(dest_ptr)
                type.free_ptr(dest_ptr)
                return js_value
            },

            cleanup: _ => Module._free(dest_ptrptr),
            // the inner dest_ptr only gets cleaned up when the call is successful (above)
        }
    }
})

// A destination pointer to an Bytes output buffer with a fixed size (without a `written` argument)
//
// `size_source` may contain a fixed size for the output buffer or the special value `USER_PROVIDED_LEN`
// to read the size as a user-provided JS argument.
types.DestPtrSized = (type, size_source) => ({

    // Consumes no user-provided JS arguments, unless USER_PROVIDED_LEN is used
    no_user_args: size_source != USER_PROVIDED_LEN,

    wasm_types: ['number', 'number'],

    to_wasm: this_arg => {
        const array_size = size_source == USER_PROVIDED_LEN ? this_arg : size_source
            , dest_ptr = type.malloc_sized(array_size)

        return {
            args: [dest_ptr, array_size],
            return: _ => type.read_ptr_sized(dest_ptr, array_size),
            cleanup: _ => type.free_ptr(dest_ptr),
        }
    }
})

export const USER_PROVIDED_LEN = types.USER_PROVIDED_LEN = {}

// A destination pointer to a variable-length Bytes output buffer (with a `written` argument)
//
// `size_source` may contain a fixed size for the output buffer or a function that calculates it.
// `size_is_upper_bound` allows the returned buffer to be smaller (truncated to the `written` size).
//
// See https://wally.readthedocs.io/en/latest/conventions/#variable-length-output-buffers
// Note that the retry mechanism described in the link above is not implemented. Instead, the
// exact (or maximum) size is figured out in advance, and an error is raised if its insufficient.
types.DestPtrVarLen = (type, size_source, size_is_upper_bound = false) => ({
    no_user_args: true,
    // the destination ptr, its size, and the destination ptr for number of bytes written/expected
    wasm_types: ['number', 'number', 'number'],

    to_wasm: (_, all_args) => {
        const array_size = typeof size_source == 'function'
            ? size_source(...all_args)
            : size_source

        const dest_ptr = type.malloc_sized(array_size)
            , written_ptr = Module._malloc(4)

        return {
            args: [dest_ptr, array_size, written_ptr],
            return: _ => {
                // This contains either the written size when the buffer was large enough, or the expected size when it was not
                const written_or_expected = Module.getValue(written_ptr, 'i32')

                if (written_or_expected == array_size) {
                    return type.read_ptr_sized(dest_ptr, array_size)
                } else if (written_or_expected < array_size && size_is_upper_bound) {
                    return type.read_ptr_sized(dest_ptr, written_or_expected)
                } else {
                    throw new WallyUnexpectedBufferSizeError(array_size, written_or_expected)
                }
            },
            cleanup: _ => (Module._free(dest_ptr), Module._free(written_ptr)),
        }
    }
})

//
// Utilities
//

export const hexToBytes = hex => new Uint8Array(Buffer.from(hex, 'hex'))

export const bytesToHex = bytes => Buffer.from(bytes).toString('hex')

//
// Errors
//

export class WallyError extends Error {
    constructor(code) {
        super(`Invalid libwally return code ${code} (${ERROR_CODES[code] || 'unknown'})`)
        this.code = code
    }
}

const ERROR_CODES = {
    [WALLY_ERROR]: 'WALLY_ERROR',
    [WALLY_EINVAL]: 'WALLY_EINVAL',
    [WALLY_ENOMEM]: 'WALLY_ENOMEM',
}

export class WallyUnexpectedBufferSizeError extends Error {
    constructor(given_size, actual_size) {
        super(`Unexpected output buffer size ${actual_size}, expected ${given_size}`)
        this.given_size = given_size
        this.actual_size = actual_size
    }
}

export class WallyArrayNumTypeError extends Error {
    constructor(given_value, expected_type) {
        super(`Expected an ${expected_type.name} array, not ${given_value}`)
    }
}

export class WallyNumArgsError extends Error {
    constructor(func_name, num_expected, num_given) {
        super(`Invalid number of arguments for ${func_name} (${num_given}, expected ${num_expected})`)
    }
}


//
// Wrap a libwally WASM function with a high-level JavaScript API
//
export function wrap(func_name, args_types) {
    const wasm_args_types = [].concat(...args_types.map(arg_type => arg_type.wasm_types || [arg_type.wasm_type]))
    const wasm_fn = Module.cwrap(func_name, 'number', wasm_args_types)
    // the return value is always the success/error code

    const js_args_num = args_types.filter(type => !type.no_user_args).length

    return function (...all_args) {
        if (all_args.length != js_args_num) {
            throw new WallyNumArgsError(func_name, js_args_num, all_args.length)
        }

        const argsc = [...all_args] // shallow clone so we can shift()
            , wasm_args = []
            , returns = []
            , cleanups = []

        try {
            // Each arg type consumes 0 or 1 user-provided JS arguments, and expands into 1 or more C/WASM arguments
            for (const arg_type of args_types) {
                // Types with `no_user_args` don't use any of the user-provided js args
                const this_arg = arg_type.no_user_args ? null : argsc.shift()

                const as_wasm = arg_type.to_wasm(this_arg, all_args)

                wasm_args.push(...as_wasm.args)
                if (as_wasm.return) returns.push(as_wasm.return)
                if (as_wasm.cleanup) cleanups.push(as_wasm.cleanup)
            }

            const code = wasm_fn(...wasm_args)

            if (code !== WALLY_OK) {
                throw new WallyError(code)
            }

            const results = returns.map(return_fn => return_fn())

            return results.length == 0 ? true // success, but no explicit return value
                : results.length == 1 ? results[0]
                    : results
        } finally {
            cleanups.forEach(cleanup_fn => cleanup_fn())
        }
    }
}