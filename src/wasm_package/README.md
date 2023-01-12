# libwally JS

Official Blockstream WASM-based JavaScript bindings for [libwally](https://github.com/elementsproject/libwally-core),
for nodejs and the browser.

## Installation

```bash
$ npm install wallycore
```

## Example use

With ES modules:

```js
import wally from 'wallycore'

const word = wally.bip39_get_word(null, 10)

const script = wally.address_to_scriptpubkey("1EMBaSSyxMQPV2fmUsdB7mMfMoocgfiMNw", wally.WALLY_NETWORK_BITCOIN_MAINNET)

const tx = wally.tx_from_hex('020000000100000000000000000000000000000000000000000000000000000000000000000000000000fdffffff0101000000000000000000000000', 0)
console.log(wally.tx_get_txid(tx).toString('hex'))
wally.tx_free(tx)
```

If you're using CommonJS, the module can be loaded asynchronously using `const wally = await import('wallycore')` or `import('wallycore').then(wally => { ... })`.

For browser use, you may use a bundler like [webpack](https://webpack.js.org/),
or use the pre-bundled [`wallycore.bundle.js`](wallycore.bundle.js) file which exposes a global `WallyInit` promise that resolves to the module. For example:

```html
<script src="wallycore/wallycore.bundle.min.js"></script>
<script>
WallyInit.then(wally => {
    console.log(wally.bip39_get_word(null, 10))
})
// or `const wally = await WallyInit`
</script>
```

## Limitations

- BIP38 (passphrase-protected keys) [related functions](https://wally.readthedocs.io/en/latest/bip38/) are disabled due to WASM memory restrictions, which are insufficient for running Scrypt with the BIP38 parameters.

## License
[BSD/MIT](https://github.com/ElementsProject/libwally-core/blob/master/LICENSE)
