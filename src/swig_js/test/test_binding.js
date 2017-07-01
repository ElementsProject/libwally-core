/* Test cases for invalid binding values/error mappings */
var wally = require('../wally');
var test = require('tape');

var undef;
var cases = [
    [ function() { wally.wally_base58_from_bytes(null, 0); },
      /TypeError/, 'null const bytes' ],
    [ function() { wally.wally_base58_from_bytes(undef, 0); },
      /TypeError/, 'undef const bytes' ],
]

test('Bindings', function (t) {
    t.plan(cases.length);
    cases.forEach(function(testCase) {
        t.throws(testCase[0], testCase[1], testCase[2]);
    })
});
