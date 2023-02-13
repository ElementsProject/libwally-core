import test from 'test'
import assert from 'assert'
import wally from '../src/index.js'

test('Confidential Address', () => {
    // The (Liquid) address that is to be blinded
    const addr = 'Q7qcjTLsYGoMA7TjUp97R6E6AM5VKqBik6'
    // The blinding pubkey
    const pubkey_hex = '02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623'
    // The resulting confidential address
    const addr_c = 'VTpz1bNuCALgavJKgbAw9Lpp9A72rJy64XPqgqfnaLpMjRcPh5UHBqyRUE4WMZ3asjqu7YEPVAnWw2EK'

    test('can extract the original address', () => {
        const res = wally.confidential_addr_to_addr(addr_c, wally.WALLY_CA_PREFIX_LIQUID)
        assert.equal(res, addr, 'Conf addr to addr')
    })

    test('can extract the blinding pubkey then re-generate the confidential address from its inputs', () => {
        const ecpubkey = wally.confidential_addr_to_ec_public_key(addr_c, wally.WALLY_CA_PREFIX_LIQUID)
        assert.equal(ecpubkey.toString('hex'), pubkey_hex, 'Extract blinding key')

        const res = wally.confidential_addr_from_addr(addr, wally.WALLY_CA_PREFIX_LIQUID, ecpubkey)
        assert.equal(res, addr_c, 'Addr to conf addr')
    })
})
