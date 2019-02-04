const wally = require('./wally');
const EC_PUBLIC_KEY_LEN = 33;
const VERSION_PREFIX_LIQUID = '4b';
var seed = Buffer.from('00000000000000000000000000000000', 'hex');

wally.wally_sha256(Buffer.from('test', 'ascii')).then(function(uint8Array) {
  console.log(Buffer.from(uint8Array).toString('hex'))
});
wally.wally_base58_from_bytes(Buffer.from('xyz', 'ascii'), 0).then(function(s) {
  console.log(s);
  wally.wally_base58_to_bytes(s, 0).then(function(bytes_) {
    console.log(Buffer.from(bytes_).toString('ascii'));
  });
});

wally.bip32_key_from_seed(seed, 0x0488ADE4, 0).then(function(s) {
  wally.wally_base58_from_bytes(s, 1).then(function (s) {
    console.log('xpriv m/0:', s);
  });

  wally.wally_ec_public_key_from_private_key(s.slice(46, 78)).then(function(master_pubkey) {
    console.log('M/0: ', Buffer.from(master_pubkey));
  });

  wally.bip32_privkey_from_parent(s, 0, 0).then(function (xpriv_0_0) {
    wally.wally_base58_from_bytes(xpriv_0_0, 1).then(function (base58_xpriv) {
      console.log('xpriv m/0/0:', base58_xpriv);
    });
  });

  wally.bip32_pubkey_from_parent(s, 0, 0).then(function (xpub_0_0) {
    wally.wally_base58_from_bytes(xpub_0_0, 1).then(function (base58_xpub) {
      console.log('xpub M/0/0:', base58_xpub);
    });

    wally.bip32_pubkey_from_parent(xpub_0_0, 1, 1).then(function (xpub_0_0_1) {
      wally.wally_base58_from_bytes(xpub_0_0_1, 1).then(function (base58_xpub) {
        console.log('xpub M/0/0/1:', base58_xpub);
      });

      var version = Buffer.from('0014', 'hex');

      wally.wally_hash160(xpub_0_0_1.slice(45, 78)).then((hash160) => {
        return wally.wally_addr_segwit_from_bytes(Buffer.concat([version, Buffer.from(hash160)]),'tb',0);
      }).then((addr) => {
        console.log('bech32: addr: ', addr)
      });
    });
  });
});

// Multisig Address
wally.bip32_key_from_seed(Buffer.from('00000000000000000000000000000000', 'hex'), 0x0488ADE4, 0)
.then(function(s) {

  //Derive child pubkey from parent xpub in bytes
  var _pubkey1 = wally.bip32_pubkey_from_parent(s, 1, 0);
  var _pubkey2 = wally.bip32_pubkey_from_parent(s, 2, 0);

  return Promise.all([_pubkey1, _pubkey2]);
  
}).then((xpubkeys) => {
  const pubkey1 = xpubkeys[0].slice(45, 78);
  const pubkey2 = xpubkeys[1].slice(45, 78);
  const byt_pubkeys = Buffer.concat([pubkey1, pubkey2]);

  // build redeem script
  return wally.wally_scriptpubkey_multisig_from_bytes(
    byt_pubkeys,
    2,
    0,
    (byt_pubkeys.byteLength / EC_PUBLIC_KEY_LEN) * 34 + 3);
}).then((redeem_script) => {
  console.log(Buffer.from(redeem_script).toString('hex'));

  // hash redeem script
  return wally.wally_hash160(redeem_script);

}).then((script_hash) => {
  const prefix = Buffer.from(VERSION_PREFIX_LIQUID, 'hex');

  // base58 encode with adding checksum
  return wally.wally_base58_from_bytes(Buffer.concat([prefix, script_hash]), 1);
  
}).then((addr) => {
  console.log('multisig addr: ', addr);
});

wally.bip32_key_from_seed(Buffer.from('00000000000000000000000000000000', 'hex'), 0x0488ADE4, 0)
.then(function(s) {

  return wally.bip32_pubkey_from_parent(s, 0, 1);
  
}).then((xpubkey) => {
  const pubkey = xpubkey.slice(45, 78);
 
  return wally.wally_hash160(pubkey);

}).then((script) => {
  const prefix = Buffer.from('eb', 'hex');

  return wally.wally_base58_from_bytes(Buffer.concat([prefix, script]), 1);

}).then((addresses) => {
  console.log(addresses);
});
