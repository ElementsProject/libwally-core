import InitWallyModule from './libwally_wasm/wallycore.cjs'
import { WALLY_OK, WALLY_ERROR, WALLY_EINVAL, WALLY_ENOMEM, WALLY_TXHASH_LEN } from './const.js'

export * from './const.js'

// Initialize the underlying WASM module and expose it publicly
const Module = await InitWallyModule()
export const WasmModule = Module

//
// Types
//

const types = {}

// Number types
types.Number = {
    wasm_type: 'number',
    to_wasm: num => ({ args: [num] }),

    read_ptr: function (ptr) { return Module.getValue(ptr, this.llvm_type) },
    free_ptr: ptr => Module._free(ptr),

    llvm_type: 'i32',
    fixed_size: 4,
}
types.Numberi8 = { ...types.Number, llvm_type: 'i8', fixed_size: 1 }
types.Numberi16 = { ...types.Number, llvm_type: 'i16', fixed_size: 2 }
types.Numberi32 = types.Number
types.Numberi64 = { ...types.Number, llvm_type: 'i64', fixed_size: 8 }
types.NumberFloat = { ...types.Number, llvm_type: 'float', fixed_size: 4 }
types.NumberDouble = { ...types.Number, llvm_type: 'double', fixed_size: 8 }

// UTF-8 null-terminated string
types.String = {
    wasm_type: 'string',
    to_wasm: str => ({ args: [str] }),

    read_ptr: ptr => Module.UTF8ToString(ptr),
    free_ptr: ptr => wally_free_string(ptr),
}

// Bytes array
// Passed to C as two arguments, the pointer and its length.
// Represented in JS as a Uint8Array.
types.Bytes = {
    wasm_types: ['array', 'number'],
    to_wasm: uint8arr => ({
        args: [uint8arr, uint8arr.length]
    }),

    read_ptr_sized: (ptr, size) =>
        new Uint8Array(Module.HEAP8.subarray(ptr, ptr + size)),
    free_ptr: ptr => Module._free(ptr),
}

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
        const dest_ptr = Module._malloc(type.fixed_size)
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

    to_wasm: _ => {
        const dest_ptr = Module._malloc(init_size)
            , written_ptr = Module._malloc(4)
        return {
            args: [dest_ptr, init_size, written_ptr],
            return: _ => {
                // this is named 'written' as in libwally, but can also mean 'expected' when the given buffer is too small
                const written = Module.getValue(written_ptr, 'i32')

                if (written > init_size) {
                    // FIXME varlen retry logic
                    throw new WallyVarLenError(init_size, written)
                }

                return types.Bytes.read_ptr_sized(dest_ptr, written)
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

//
// Functions
//

// Wrap a libwally WASM function with a high-level JavaScript API
function wrap(func_name, args_types) {
    const wasm_args_types = [].concat(...args_types.map(arg_type => arg_type.wasm_types || [arg_type.wasm_type]))
    const wasm_fn = Module.cwrap(func_name, 'number', wasm_args_types)
    // the return value is always the success/error code

    const js_args_num = args_types.filter(type => !type.no_user_args).length

    return function (...args) {
        if (args.length != js_args_num) {
            throw new Error(`Invalid number of arguments for ${func_name} (${args.length}, expected ${js_args_num})`)
        }

        const wasm_args = []
            , returns = []
            , cleanups = []

        // Each arg type consumes 0 or 1 user-provided JS arguments, and expands into 1 or more C/WASM arguments
        for (const arg_type of args_types) {
            // Types with `no_user_args` don't use any of the user-provided js args
            const arg_value = arg_type.no_user_args ? null : args.shift()

            const as_wasm = arg_type.to_wasm(arg_value)

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
}

export const wally_address_to_scriptpubkey = wrap('wally_address_to_scriptpubkey', [
    types.String,
    types.Number,
    types.DestPtrVarLen(100),
])


export const wally_wif_is_uncompressed = wrap('wally_wif_is_uncompressed', [
    types.String,
    types.DestPtr(types.Number)
])

export const wally_wif_from_bytes = wrap('wally_wif_from_bytes', [
    types.Bytes, // private key
    types.Number, // prefix
    types.Number, // flags
    types.DestPtrPtr(types.String)
])

export const bip39_get_word = wrap('bip39_get_word', [
    types.OpaqueRef,
    types.Number,
    types.DestPtrPtr(types.String)
])
export const bip39_mnemonic_from_bytes = wrap('bip39_mnemonic_from_bytes', [
    types.OpaqueRef,
    types.Bytes,
    types.DestPtrPtr(types.String),
])

export const wally_hex_verify = wrap('wally_hex_verify', [types.String])


export const wally_tx_from_bytes = wrap('wally_tx_from_bytes', [
    types.Bytes,
    types.Number,
    types.DestPtrPtr(types.OpaqueRef),
])
export const wally_tx_from_hex = wrap('wally_tx_from_hex', [
    types.String,
    types.Number,
    types.DestPtrPtr(types.OpaqueRef),
])

export const wally_tx_get_witness_count = wrap('wally_tx_get_witness_count', [
    types.OpaqueRef,
    types.DestPtr(types.Number),
])

export const wally_tx_get_txid = wrap('wally_tx_get_txid', [
    types.OpaqueRef,
    types.DestPtrSized(WALLY_TXHASH_LEN),
])

export const wally_free_string = wrap('wally_free_string', [types.OpaqueRef])

export const wally_tx_free = wrap('wally_tx_free', [types.OpaqueRef])