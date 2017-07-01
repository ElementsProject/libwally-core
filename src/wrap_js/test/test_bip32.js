var wally = require('../wally');
var test = require('tape');

test('BIP32 from seed + derivation', function(t) {
  t.plan(2);
  var zeroes = [];
  for (var i = 0; i < 16; ++i) {
    zeroes.push(0);
  }
  wally.bip32_key_from_seed(new Buffer(zeroes), 0x0488ADE4, 0).then(function(s) {
    wally.wally_base58_from_bytes(s, 1).then(function (s) {
      t.equal(
        s,
        ('xprv9s21ZrQH143K2JbpEjGU94NcdKSASB7LuXvJCTsxuENcGN1nVG7Q'+
         'jMnBZ6zZNcJaiJogsRaLaYFFjs48qt4Fg7y1GnmrchQt1zFNu6QVnta'),
        'privkey'
      );
    });
    wally.bip32_pubkey_from_parent(s, 1, 0).then(function (pub) {
      wally.wally_base58_from_bytes(pub, 1).then(function (s) {
        t.equal(
          s,
          ('xpub683nVy7Tt7baCKuqho7X5C7TGuskZAa4wQ5YEue2BxtYB6upN4Yg'+
           'WTyZYnLg56XDFt7YN3DrFZEYmEhMqpsZmiP73NNrR5P8WcbfWgfQGGi'),
          'pubkey'
        );
      });
    });
  });
});
