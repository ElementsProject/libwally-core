import wally from '../src/index.js'
import test from 'test'
import assert from 'assert'

const cases = []
// Leading zeros become ones
for (let i = 1; i < 10; ++i) {
    let ones = ''
    for (let j = 0; j < i; ++j) ones += '1'
    cases.push([[new Uint8Array(i), 0], ones])
}
cases.push([[Buffer.from('00CEF022FA', 'hex'), 0], '16Ho7Hs'])
cases.push([[Buffer.from('45046252208D', 'hex'), 1], '4stwEBjT6FYyVV'])

test('base58 from bytes', () => {
    cases.forEach((testCase) => {
        const s = wally.base58_from_bytes(testCase[0][0], testCase[0][1])
        assert.deepEqual(s, testCase[1],
            'base58_from_bytes(' +
            Buffer.from(testCase[0][0]).toString('hex') + ',' + testCase[0][1] + ')')
    })
})

test('base58 to bytes', () => {
    cases.forEach((testCase) => {
        const d = wally.base58_to_bytes(testCase[1], testCase[0][1])
        assert.deepEqual(Buffer.from(d), Buffer.from(testCase[0][0]),
            'base58_to_bytes(' + testCase[1] + ',' + testCase[0][1] + ')')
    })
})