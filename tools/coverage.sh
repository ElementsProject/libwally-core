#/bin/bash

# To generate coverage:
# $ ./configure --enable-debug --enable-coverage ...
# $ make
# $ ./tools/coverage.sh clean
# $ make test
# $ ./tools/coverage.sh
# $ firefox src/lcov/index.html

lcov="lcov --directory=src/ --base-directory src/"

if [ $1 = "clean" ]; then
    $lcov --zerocounters
    $lcov --output-file src/lcov_base --capture --initial
else
    $lcov --output-file src/lcov_result --capture --ignore-errors=gcov
    $lcov --output-file src/lcov_total --add-tracefile src/lcov_base --add-tracefile src/lcov_result --ignore-errors=gcov
    genhtml --demangle-cpp -o src/lcov/ src/lcov_total
fi
