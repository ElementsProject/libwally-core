// Minimal shim for nodejs's assert module, for the browser
// For some reason, this doesn't work with the https://github.com/browserify/commonjs-assert shim,
// which causes the webpack bundle to hang when attempting to import it.

export default function assert(val, err='assertion failed') {
    if (!val) throw err
}
