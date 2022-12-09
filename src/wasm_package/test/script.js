import test from 'test'
import assert from 'assert'
import wally from '../src/index.js'

test('scriptpubkey_multisig_from_bytes', () => {
    const pubkeys = [
        '02ad4199d0c53b564b39798c4c064a6e6093abbb71d56cc153abf75a02f85c8e99',
        '03afeefeba0806711b6d3fc7c8b0b6a3eff5ea2ecf938aea1b6a093898097875f3'
    ]
    const pubkey_bytes = Buffer.from(pubkeys[0] + pubkeys[1], 'hex')
    const redeem_script = '522102ad4199d0c53b564b39798c4c064a6e6093abbb71d56cc153abf75a02f85c8e992103afeefeba0806711b6d3fc7c8b0b6a3eff5ea2ecf938aea1b6a093898097875f352ae'

    const res = wally.scriptpubkey_multisig_from_bytes(pubkey_bytes, 2, 0)
    assert.equal(res.toString('hex'), redeem_script)
})

test('scriptpubkey_p2pkh_from_bytes', () => {
    const redeem1 = Buffer.from("111111111111111111111111111111111111111111111111111111111111111111", "hex")
    assert.equal(wally.scriptpubkey_p2pkh_from_bytes(redeem1, wally.WALLY_SCRIPT_HASH160).toString('hex'), "76a9148ec4cf3ee160b054e0abb6f5c8177b9ee56fa51e88ac",
        "Unexpected p2pkh result")

    const redeem2 = Buffer.from("1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111", "hex")
    assert.equal(wally.scriptpubkey_p2pkh_from_bytes(redeem2, wally.WALLY_SCRIPT_HASH160).toString('hex'), "76a914e723a0f62396b8b03dbd9e48e9b9efe2eb704aab88ac",
        "Unexpected p2pkh result")
})

test('scriptpubkey_p2sh_from_bytes', () => {
    const redeem1 = Buffer.from("0020a22f2fcda841261e29973ad0191130911c5fd95eeec58de8e9367223b5dc040e", "hex")
    assert.equal(wally.scriptpubkey_p2sh_from_bytes(redeem1, wally.WALLY_SCRIPT_HASH160).toString('hex'), "a914822866d2b6a573a313e124bb1881a2f7ac4954ec87",
        "Unexpected p2sh result")

    const redeem2 = Buffer.from("002028a8fc70e1299f8728f62f2fe4ab98ef3af6e1af0bd46b2b924fa22092af00b8", "hex")
    assert.equal(wally.scriptpubkey_p2sh_from_bytes(redeem2, wally.WALLY_SCRIPT_HASH160).toString('hex'), "a914faf609ab5e82fbe8f6fcf0dcb2d4359dd044d2d387",
        "Unexpected p2sh result")
})