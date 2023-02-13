// Combining functions.js + const.js + core.js as the default export requires a separate
// exports.js file that unifies them as named exports.
// With this, library users can `import wally from 'wallycore'`, without `* as`

export * from './exports.js'
export * as default from './exports.js'

import { webcrypto } from 'crypto'
import { init, secp_randomize } from './functions.js'
import { WALLY_SECP_RANDOMIZE_LEN } from './const.js'

// Initialize libwally and seed it with the browser/nodejs's CSPRNG

init(0)

const randomBytes = new Uint8Array(WALLY_SECP_RANDOMIZE_LEN)
webcrypto.getRandomValues(randomBytes)
secp_randomize(randomBytes)