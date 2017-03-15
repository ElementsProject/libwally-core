var wally = require('./wally');

wally.wally_sha256(new Buffer('test', 'ascii')).then(function(uint8Array) {
  console.log(new Buffer(uint8Array).toString('hex'))
});
wally.wally_base58_from_bytes(new Buffer('xyz', 'ascii'), 0).then(function(s) {
  console.log(s);
  wally.wally_base58_to_bytes(s, 0).then(function(bytes_) {
    console.log(new Buffer(bytes_).toString('ascii'));
  });
});
wally.bip32_key_from_seed(new Buffer(16), 0x0488ADE4, 0).then(function(s) {
  wally.wally_base58_from_bytes(s, 1).then(function (s) {
    console.log('privkey:', s);
  });
  wally.bip32_pubkey_from_parent(s, 1, 0).then(function (pub) {
    wally.wally_base58_from_bytes(pub, 1).then(function (s) {
      console.log('pubkey:', s);
    });
  });
});
