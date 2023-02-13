import { fileURLToPath } from 'url'
import fs from 'fs'
import path from 'path'
import assert from 'assert'
import test from 'test'

import wally from '../src/index.js'

const filepath = path.resolve(fileURLToPath(import.meta.url), '../../../data/wordlists/vectors.json')
    , cases = JSON.parse(fs.readFileSync(filepath, 'utf8'))['english']
    , passphrase = 'TREZOR'

test('BIP39', () => {
    assert.equal(wally.bip39_get_languages(), 'en es fr it jp zhs zht')

    const english = wally.bip39_get_wordlist('en')

    cases.forEach(item => {
        assert.equal(wally.bip39_mnemonic_from_bytes(english, Buffer.from(item[0], 'hex')), item[1])
        assert.deepEqual(wally.bip39_mnemonic_to_seed512(item[1], passphrase).toString('hex'), item[2])
    })
})