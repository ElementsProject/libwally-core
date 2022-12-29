// Combining functions.js + const.js + core.js as the default export requires a separate
// exports.js file that unifies them as named exports.
// With this, library users can `import wally from 'wallycore'`, without `* as`

export * from './exports.js'
export * as default from './exports.js'