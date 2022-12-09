import test from 'test'
import wally from '../src/index.js'
import assert from 'assert'

const ONES = "1111111111111111111111111111111111111111111111111111111111111111";

test('asset blinding', () => {
    // hexes from local regtest testing
    const asset = wally.hex_to_bytes(ONES)
    const abf = wally.hex_to_bytes(ONES)
    const generator = wally.asset_generator_from_bytes(asset, abf)

    const values = [20000n, 4910n, 13990n, 1100n]
    const last_vbf = wally.asset_final_vbf(values, 1,
        wally.hex_to_bytes("7fca161c2b849a434f49065cf590f5f1909f25e252f728dfd53669c3c8f8e37100000000000000000000000000000000000000000000000000000000000000002c89075f3c8861fea27a15682d664fb643bc08598fe36dcf817fcabc7ef5cf2efdac7bbad99a45187f863cd58686a75135f2cc0714052f809b0c1f603bcdc574"),
        wally.hex_to_bytes("1c07611b193009e847e5b296f05a561c559ca84e16d1edae6cbe914b73fb6904000000000000000000000000000000000000000000000000000000000000000074e4135177cd281b332bb8fceb46da32abda5d6dc4d2eef6342a5399c9fb3c48"))

    assert.equal(
        wally.hex_from_bytes(last_vbf), "6996212c70fa85b82d4fd76bd262e0cebc5d8f52350a73af8d2b881a30442b9d",
        "Unexpected asset_final_vbf result"
    )
})

test('blinding keys', () => {
    // hexes from local regtest testing
    const seed = wally.hex_to_bytes("fecd7938b912091cdedb47f70d4f3742f59f77e3bac780c0c498e2aaf6f9f4ab")
    const master_blinding_key = wally.asset_blinding_key_from_seed(seed)

    assert.equal(
        wally.hex_from_bytes(master_blinding_key), "624d15c603de16a92081fece31b9f21ac53ff6cb00f4180b0021adf754b161c9aa44ecaa161502f3b9a84122179a4320524ab1807578ee291360c2133f445233",
        "Unexpected master_blinding_key result"
    )

    const scriptpubkey = wally.hex_to_bytes("a914822866d2b6a573a313e124bb1881a2f7ac4954ec87")
    const private_blinding_key = wally.asset_blinding_key_to_ec_private_key(master_blinding_key, scriptpubkey)

    assert.equal(
        wally.hex_from_bytes(private_blinding_key), "358876bdb32f60b8cdb811e922600b36b4d2b752d1869cccd9d79c566f45d87a",
        "Unexpected private_blinding_key result"
    )

    const public_blinding_key = wally.ec_public_key_from_private_key(private_blinding_key)

    assert.equal(
        wally.hex_from_bytes(public_blinding_key), "03df03058b2d4032471b0937c2401aa728e1403f4bce0fa62d917cff874c87bd45",
        "Unexpected public_blinding_key result"
    )
})

test('symmetric', () => {
    // Just test our wrappers; the values are tested by test_blinding_keys() above
    const seed = wally.hex_to_bytes("fecd7938b912091cdedb47f70d4f3742f59f77e3bac780c0c498e2aaf6f9f4ab")
    const master_key = wally.symmetric_key_from_seed(seed)
    const child_key = wally.symmetric_key_from_parent(master_key, 0, Buffer.from("foo"))
})

test('confidential address', () => {
    // hexes from local regtest testing
    const addr = "Q7qcjTLsYGoMA7TjUp97R6E6AM5VKqBik6"
    const pubkey_hex = "02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623"
    const addr_c = "VTpz1bNuCALgavJKgbAw9Lpp9A72rJy64XPqgqfnaLpMjRcPh5UHBqyRUE4WMZ3asjqu7YEPVAnWw2EK"

    const new_addr = wally.confidential_addr_to_addr(addr_c, wally.WALLY_CA_PREFIX_LIQUID)
    assert.equal(
        new_addr, addr,
        "Failed to extract address from confidential address"
    )

    const pubkey = wally.confidential_addr_to_ec_public_key(addr_c, wally.WALLY_CA_PREFIX_LIQUID)
    assert.equal(
        wally.hex_from_bytes(pubkey), pubkey_hex,
        "Failed to extract pubkey from confidential address"
    )

    const new_addr_c = wally.confidential_addr_from_addr(addr, wally.WALLY_CA_PREFIX_LIQUID, pubkey)
    assert.equal(
        new_addr_c, addr_c,
        "Failed to create confidential address"
    )
})

test('confidential values', () => {
    const hex_values = ["010000000002faf080", "010000000002fa2d30", "01000000000000c350"]
    const long_values = [50000000n, 49950000n, 50000n]

    for (let i = 0; i < long_values.length; ++i) {
        assert.equal(
            hex_values[i], wally.hex_from_bytes(wally.tx_confidential_value_from_satoshi(long_values[i])),
            "Unexpected confidential value"
        )

        assert.equal(
            long_values[i], wally.tx_confidential_value_to_satoshi(wally.hex_to_bytes(hex_values[i])),
            "Unexpected long satoshi value"
        )
    }
})