# libwally JS

WASM-based JavaScript bindings for [libwally](https://github.com/elementsproject/libwally-core),
for nodejs and the browser.

## Installation

```bash
$ npm install wallycore
```

## Example use

```js
import wally from 'wallycore'

const word = wally.bip39_get_word(null, 10)

const script = wally.address_to_scriptpubkey("1EMBaSSyxMQPV2fmUsdB7mMfMoocgfiMNw", wally.WALLY_NETWORK_BITCOIN_MAINNET)

const tx = wally.tx_from_hex('020000...', 0)
console.log(wally.tx_get_txid(tx).toString('hex))
wally.tx_free(tx)
```

If you're using CommonJS, the module can be loaded asynchronously using `const wally = await import('wallycore')` or `import('wallycore').then(wally => { ... })`.

## License
[BSD/MIT](https://github.com/ElementsProject/libwally-core/blob/master/LICENSE)