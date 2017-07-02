/* Test cases for invalid binding values/error mappings */
var wally = require('../wally');
var test = require('tape');

var undef;
var valid = new Buffer('00CEF022FA', 'hex');

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
]

test('Bindings', function (t) {
    t.plan(cases.length);
    cases.forEach(function(testCase) {
        t.throws(testCase[0], testCase[1], testCase[2]);
    })
});
