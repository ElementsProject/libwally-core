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
    free_ptr: ptr => _wally_free_string(ptr),
}
const _wally_free_string = Module.cwrap('wally_free_string', 'number', ['number'])

// Array of integers. Used for byte buffers and 32/64 bits numbers.
// Passed to C as two arguments, the pointer and the array length.
// Represented in JS as the IntArrayType, which is a Uint{8,32,64}Array.
types.IntArray = IntArrayType => ({
    wasm_types: ['array', 'number'],
    to_wasm: int_arr => {
        if (Array.isArray(int_arr)) {
            // Try coercing standard Arrays into the expected IntArrayType.
            // This will fail if the array values don't match the int type.
            int_arr = new IntArrayType(int_arr)
        } else if (!(int_arr instanceof IntArrayType)) {
            throw new WallyArrayNumTypeError(int_arr, IntArrayType)
        }

        return {
            args: [int_arr, int_arr.length]
        }
    },

    read_ptr_sized: (ptr, size) =>
        new IntArrayType(Module.HEAP8.subarray(ptr, ptr + size)),

    free_ptr: ptr => Module._free(ptr),
})

types.Bytes = types.IntArray(Uint8Array)
types.Uint32Array = types.IntArray(Uint32Array)
types.Uint64Array = types.IntArray(BigUint64Array)

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

// A destination pointer to a Bytes buffer with a known size
types.DestPtrSized = size => ({
    no_user_args: true,
    wasm_types: ['number', 'number'],
    to_wasm: _ => {
        const dest_ptr = Module._malloc(size)
        return {
            args: [dest_ptr, size],
            return: _ => types.Bytes.read_ptr_sized(dest_ptr, size),
            cleanup: _ => types.Bytes.free_ptr(dest_ptr),
        }
    }
})

// A destination pointer to a variable length Bytes buffer
// See https://wally.readthedocs.io/en/latest/conventions/#variable-length-output-buffers
types.DestPtrVarLen = init_size => ({
    no_user_args: true,
    // the destination ptr, its size, and the destination ptr for number of bytes written/expected
    wasm_types: ['number', 'number', 'number'],

    to_wasm: (_, extra_type_info) => {
        // Use the expected size if its already known, or try with the initial size which is hopefully large enough
        const dest_ptr_size = extra_type_info.expected_varlen_size || init_size
            , dest_ptr = Module._malloc(dest_ptr_size)
            , written_ptr = Module._malloc(4)

        return {
            args: [dest_ptr, dest_ptr_size, written_ptr],
            return: _ => {
                // This contains either the written size when the buffer was large enough, or the expected size when it was not
                const written_or_expected = Module.getValue(written_ptr, 'i32')

                if (written_or_expected > dest_ptr_size) {
                    // Caught outside to trigger a retry with the expected size
                    throw new WallyVarLenError(dest_ptr_size, written_or_expected)
                }

                return types.Bytes.read_ptr_sized(dest_ptr, written_or_expected)
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

export class WallyVarLenError extends Error {
    constructor(given_size, expected_size) {
        super(`Insufficient output buffer size, ${expected_size} needed but only ${given_size} given`)
        this.given_size = given_size
        this.expected_size = expected_size
    }
}

export class WallyArrayNumTypeError extends Error {
    constructor(given_value, expected_type) {
        super(`Expected an ${expected_type.name} array, not ${given_value}`)
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

    return function (...args) {
        if (args.length != js_args_num) {
            // TODO specialized error
            throw new Error(`Invalid number of arguments for ${func_name} (${args.length}, expected ${js_args_num})`)
        }

        function run(extra_type_info = {}) {
            const argsc = [...args] // shallow clone so we can shift()
                , wasm_args = []
                , returns = []
                , cleanups = []

            // Each arg type consumes 0 or 1 user-provided JS arguments, and expands into 1 or more C/WASM arguments
            for (const arg_type of args_types) {
                // Types with `no_user_args` don't use any of the user-provided js args
                const arg_value = arg_type.no_user_args ? null : argsc.shift()

                const as_wasm = arg_type.to_wasm(arg_value, extra_type_info)

                wasm_args.push(...as_wasm.args)
                if (as_wasm.return) returns.push(as_wasm.return)
                if (as_wasm.cleanup) cleanups.push(as_wasm.cleanup)
            }

            try {
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

        try {
            return run()
        } catch (err) {
            // Retry with the expected buffer size when the buffer we provided is too small (but only once)
            // See https://wally.readthedocs.io/en/latest/conventions/#variable-length-output-buffers
            if (err instanceof WallyVarLenError) {
                return run({ expected_varlen_size: err.expected_size })
            } else {
                throw err
            }
        }
    }
}