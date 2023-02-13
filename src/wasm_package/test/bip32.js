import test from 'test'
import assert from 'assert'
import wally from '../src/index.js'

const seed = Buffer.from('00000000000000000000000000000000', 'hex')

test('BIP32 from seed + derivation', () => {
  const bkey = wally.bip32_key_from_seed(Buffer.from(seed), wally.BIP32_VER_MAIN_PRIVATE, wally.BIP32_FLAG_KEY_PRIVATE)
  const sBase58 = wally.bip32_key_to_base58(bkey, wally.BIP32_FLAG_KEY_PRIVATE)
  assert.equal(
    sBase58,
    ('xprv9s21ZrQH143K2JbpEjGU94NcdKSASB7LuXvJCTsxuENcGN1nVG7Q' +
      'jMnBZ6zZNcJaiJogsRaLaYFFjs48qt4Fg7y1GnmrchQt1zFNu6QVnta'),
    'privkey'
  )

  const pub = wally.bip32_key_from_parent(bkey, 1, wally.BIP32_FLAG_KEY_PRIVATE)
  const pubBase58 = wally.bip32_key_to_base58(pub, wally.BIP32_FLAG_KEY_PUBLIC)
  assert.equal(
    pubBase58,
    ('xpub683nVy7Tt7baCKuqho7X5C7TGuskZAa4wQ5YEue2BxtYB6upN4Yg' +
      'WTyZYnLg56XDFt7YN3DrFZEYmEhMqpsZmiP73NNrR5P8WcbfWgfQGGi'),
    'pubkey'
  )
  wally.bip32_key_free(pub)

  const privkey = wally.bip32_key_get_priv_key(bkey)
  const masterPubkey = wally.ec_public_key_from_private_key(privkey)
  assert.equal(
    Buffer.from(masterPubkey).toString('hex'),
    '02be99138b48b430a8ee40bf8b56c8ebc584c363774010a9bfe549a87126e61746',
    'm->pub'
  )

  const xpriv_0 = wally.bip32_key_from_parent(bkey, 0, wally.BIP32_FLAG_KEY_PRIVATE)
  const base58_xpriv = wally.bip32_key_to_base58(xpriv_0, wally.BIP32_FLAG_KEY_PRIVATE)
  assert.equal(
    base58_xpriv,
    'xprv9u4S6Taa3k3GxnaHfWzboKwLPPPHpDyDHdLGqDArBejguBuv6GkerLy6MtAeFfo9RDfZy22FWEc1ExEShuRGZJpgVgeVu5KZ5obWbV2R3D2',
    'm/0'
  )
  wally.bip32_key_free(xpriv_0)

  const xpub_0 = wally.bip32_key_from_parent(bkey, 0, wally.BIP32_FLAG_KEY_PRIVATE)
  const base58_xpub = wally.bip32_key_to_base58(xpub_0, wally.BIP32_FLAG_KEY_PUBLIC)
  assert.equal(
    base58_xpub,
    'xpub683nVy7Tt7baBGekmYXcATt4wRDnDgh4erFsdbaTjzGfmzF4dp4uQ9HaDCdvSqctrsbxZey5wozKyyy2J3zhDDHU3UhW4uCFQp6bESv8ewQ',
    'M/0'
  )

  const xpub_0_1 = wally.bip32_key_from_parent(xpub_0, 1, wally.BIP32_FLAG_KEY_PUBLIC)
  const base58_xpub_0_1 = wally.bip32_key_to_base58(xpub_0_1, wally.BIP32_FLAG_KEY_PUBLIC)
  assert.equal(
    base58_xpub_0_1,
    'xpub6An6e2ai6kSDnnxJ3876JwfeigdQu9YNudcP7ayT828xDFzFQkP9oBoBNdvj7xDrDQd9TQDpzkLhM5L71rFDTmxMuzSvXwZKnLx56Es6MEg',
    'M/0/1'
  )

  wally.bip32_key_free(xpub_0)
  wally.bip32_key_free(xpub_0_1)
  wally.bip32_key_free(bkey)
})

test('BIP32 from seed to address', () => {
  const bkey = wally.bip32_key_from_seed(seed, wally.BIP32_VER_MAIN_PRIVATE, wally.BIP32_FLAG_KEY_PRIVATE)
  const xpubkey = wally.bip32_key_from_parent(bkey, 0, wally.BIP32_FLAG_KEY_PUBLIC)
  const pubkey = wally.bip32_key_get_pub_key(xpubkey)
  const script = wally.hash160(pubkey)
  const prefix = Buffer.from('eb', 'hex')
  const address = wally.base58_from_bytes(Buffer.concat([prefix, Buffer.from(script)]), wally.BASE58_FLAG_CHECKSUM)
  assert.equal(
    address,
    '2dmvtD27wpRyLK79FsAidyS33uUogsYNC4U',
    'address'
  )
  wally.bip32_key_free(bkey)
})

test('BIP32 serialization', () => {
  const hex = '0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55' +
    'a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817c' +
    'db01a1494b917c8436b35'
  const unserialized = wally.bip32_key_unserialize(Buffer.from(hex, 'hex'))
  const newSerialized = wally.bip32_key_serialize(unserialized, wally.BIP32_FLAG_KEY_PRIVATE)

  assert.equal(wally.hex_from_bytes(newSerialized), hex, 'BIP32 serialization did not round-trip correctly')
  wally.bip32_key_free(unserialized)
})

test('BIP32 derivation', () => {
  const seed = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex')
  const seedKey = wally.bip32_key_from_seed(seed, wally.BIP32_VER_MAIN_PRIVATE, 0)
  const derivedKey = wally.bip32_key_from_parent(seedKey, 0, wally.BIP32_FLAG_KEY_PRIVATE)
  const derivedChainCode = wally.bip32_key_get_chain_code(derivedKey)

  assert.equal(derivedChainCode.length, 32, 'BIP32 incorrect chain code')
  assert.equal(wally.bip32_key_get_depth(derivedKey), 1, 'BIP32 incorrect depth')

  const initKey = wally.bip32_key_init(wally.bip32_key_get_version(derivedKey),
    wally.bip32_key_get_depth(derivedKey),
    wally.bip32_key_get_child_num(derivedKey),
    wally.bip32_key_get_chain_code(derivedKey),
    wally.bip32_key_get_pub_key(derivedKey),
    wally.bip32_key_get_priv_key(derivedKey),
    wally.bip32_key_get_hash160(derivedKey),
    wally.bip32_key_get_parent160(derivedKey))

  const derivedSerialized = wally.bip32_key_serialize(derivedKey, wally.BIP32_FLAG_KEY_PRIVATE)
  const initSerialized = wally.bip32_key_serialize(initKey, wally.BIP32_FLAG_KEY_PRIVATE)

  assert.deepEqual(initSerialized, derivedSerialized, 'BIP32 initialisation by member failed')

  wally.bip32_key_free(seedKey)
  wally.bip32_key_free(derivedKey)
  wally.bip32_key_free(initKey)
})