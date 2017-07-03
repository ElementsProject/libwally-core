/* Test cases for invalid binding values/error mappings */
var wally = require('../wally');
var test = require('tape');

var undef;
var valid = new Buffer('00CEF022FA', 'hex');
var h = function (h) { return new Buffer(h, 'hex'); };
var vbf = h("8b5d87d94b9f54dc5dd9f31df5dffedc974fc4d5bf0d2ee1297e5aba504ccc26");
var generator = h("0ba4fd25e0e2108e55aec683810a8652f9b067242419a1f7cc0f01f92b4b078252");

var cases = [
    [ function() { wally.wally_base58_from_bytes(null, 0); },
      /TypeError/, 'null const bytes' ],
    [ function() { wally.wally_base58_from_bytes(undef, 0); },
      /TypeError/, 'undefined const bytes' ],
    [ function() { wally.wally_base58_from_bytes(20, 0); },
      /TypeError/, 'non-buffer const bytes' ],
    /* FIXME: Argument count isn't checked yet
    [ function() { wally.wally_base58_from_bytes(); },
      /TypeError/, 'too few arguments' ],
    [ function() { wally.wally_base58_from_bytes(null, 0, 0); },
      /TypeError/, 'too many arguments' ],
       FIXME */
    [ function() { wally.wally_base58_from_bytes(valid, null); },
      /TypeError/, 'null uint32_t' ],
    [ function() { wally.wally_base58_from_bytes(valid, undef); },
      /TypeError/, 'undefined uint32_t' ],
    [ function() { wally.wally_base58_from_bytes(valid, -1); },
      /TypeError/, 'negative uint32_t' ],
    [ function() { wally.wally_base58_from_bytes(valid, 4294967296+1); },
      /TypeError/, 'overflow uint32_t' ],
    [ function() { wally.wally_base58_from_bytes(valid, valid); },
      /TypeError/, 'non-integer uint32_t' ],
    [ function() { wally.wally_asset_value_commitment(null, vbf, generator); },
      /TypeError/, 'null uint64_t' ],
    [ function() { wally.wally_asset_value_commitment(undef, vbf, generator); },
      /TypeError/, 'undefined uint64_t' ],
    [ function() { wally.wally_asset_value_commitment(10, vbf, generator); },
      /TypeError/, 'non-integer uint64_t' ],
]

test('Bindings', function (t) {
    t.plan(cases.length);
    cases.forEach(function(testCase) {
        t.throws(testCase[0], testCase[1], testCase[2]);
    })
});
