var wally = require('../wally');
var test = require('tape');

var valid_cases = [];
valid_cases.push(['BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4', 'bc', 0, '0014751e76e8199196d454941c45d1b3a323f1433bd6']);
valid_cases.push(['tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7', 'tb', 0, '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262']);
valid_cases.push(['tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy', 'tb', 0, '0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433']);

// witness version != 0
var fail_cases = [];
fail_cases.push(['bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx', 'bc', 1, '5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6']);
fail_cases.push(['BC1SW50QA3JX3S', 'bc', 16, '6002751e']);
fail_cases.push(['bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj', 'bc', 2, '5210751e76e8199196d454941c45d1b3a323']);

fail_cases.push(["tb", 'tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty']); // Invalid human-readable part
fail_cases.push(["bc", 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5']); // Invalid checksum
fail_cases.push(["bc", 'BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2']); // Invalid witness version
fail_cases.push(["bc", 'bc1rw5uspcuh']); // Invalid program length
fail_cases.push(["bc", 'bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90']); // Invalid program length
fail_cases.push(["bc", 'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P']); // Invalid program length for witness version 0 (per BIP141)
fail_cases.push(["tb", 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7']); // Mixed case
fail_cases.push(["bc", 'bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du']); // zero padding of more than 4 bits
fail_cases.push(["tb", 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv']); // Non-zero padding in 8-to-5 conversion
fail_cases.push(["bc", 'bc1gmk9yu']); // Empty data section

test('addr segwit to bytes', function (t) {
  t.plan(2 * valid_cases.length + 2 * fail_cases.length);
  valid_cases.forEach(function(testCase) {
    wally.wally_addr_segwit_to_bytes(
      testCase[0], testCase[1], 0
    ).then(function(d) {
      t.equal(new Buffer(d).toString('hex'),
      testCase[3],
        'addr_segwit_to_bytes('+testCase[0]+','+testCase[1]+')');
    })
  });

  valid_cases.forEach(function(testCase) {
    wally.wally_addr_segwit_from_bytes(
      new Buffer(testCase[3], 'hex'), testCase[1], 0
    ).then(function(d) {
      t.equal(d.toLowerCase(), testCase[0].toLowerCase(),
        'addr_segwit_from_bytes('+testCase[3]+','+testCase[1]+')');
    })
  });

  fail_cases.forEach(function(testCase) {
    t.throws(function() {
      wally.wally_addr_segwit_to_bytes(testCase[0], testCase[1], 0);
    }, new TypeError());
  });

  fail_cases.forEach(function(testCase) {
    t.throws(function() {
      wally.wally_addr_segwit_from_bytes(new Buffer(testCase[3], 'hex'), testCase[1], 0);
    }, new TypeError());
  });
});
