# Build-only check that the libwally amalgamation compiles and links against
# ESP-IDF 6.x with the PSA Crypto hashing backend (HAVE_PSA_CRYPTO_H).
#
#   . $IDF_PATH/export.sh
#   cd contrib/esp-idf-psa-check
#   idf.py set-target esp32s3
#   idf.py build
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(wally_psa_check)
