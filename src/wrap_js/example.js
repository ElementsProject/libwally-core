const wally = require('./wally');

wally.wally_sha256(Buffer.from('test', 'ascii')).then(function(uint8Array) {
  console.log(Buffer.from(uint8Array).toString('hex'))
});
wally.wally_base58_from_bytes(Buffer.from('xyz', 'ascii'), 0).then(function(s) {
  console.log(s);
  wally.wally_base58_to_bytes(s, 0).then(function(bytes_) {
    console.log(Buffer.from(bytes_).toString('ascii'));
  });
});

const seed = Buffer.from('00000000000000000000000000000000', 'hex');
wally.bip32_key_from_seed(seed, wally.BIP32_VER_MAIN_PRIVATE, 0).then(function(s) {
  wally.wally_base58_from_bytes(s, 1).then(function (s) {
    console.log('privkey:', s);
  });
  wally.bip32_pubkey_from_parent(s, 1, 0).then(function (pub) {
    wally.wally_base58_from_bytes(pub,  wally.BASE58_FLAG_CHECKSUM).then(function (s) {
      console.log('pubkey:', s);
    });
  });
});
