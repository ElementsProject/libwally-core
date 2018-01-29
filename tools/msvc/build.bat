set LIBWALLY_DIR=%cd%

REM Need to first build gen_context.exe to generate a header file
REM It seems possible to skip this step and remove the definition
REM of USE_ECMULT_STATIC_PRECOMPUTATION  from the compiler flags
call "%~dp0\gen_ecmult_static_context.bat"

REM There are files called hex.c in both the wally and ccan sources
REM In a sane build system this would not be a problem but because
REM everything is being munged together for Windows as a hack it causes
REM problems. Make a copy called hex_.c as a workaround.
copy src\ccan\ccan\str\hex\hex.c src\ccan\ccan\str\hex\hex_.c

REM Compile everything (wally, ccan, libsecp256k) in one lump.
REM Define USE_ECMULT_STATIC_PRECOMPUTATION  to pick up the
REM ecmult_static_context.h file generated previously
cl /DUSE_ECMULT_STATIC_PRECOMPUTATION /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /I%LIBWALLY_DIR%\src\wrap_js\windows_config /I%LIBWALLY_DIR% /I%LIBWALLY_DIR%\src /I%LIBWALLY_DIR%\include /I%LIBWALLY_DIR%\src\ccan /I%LIBWALLY_DIR%\src\secp256k1 /Zi /LD src/aes.c src/base58.c src/bip32.c src/bip38.c src/bip39.c src/elements.c src/hex.c src/hmac.c src/internal.c src/mnemonic.c src/pbkdf2.c src/scrypt.c src/sign.c src/wordlist.c src/ccan/ccan/crypto/ripemd160/ripemd160.c src/ccan/ccan/crypto/sha256/sha256.c src/ccan/ccan/crypto/sha512/sha512.c src\ccan\ccan\str\hex\hex_.c src/secp256k1/src/secp256k1.c /Fewally.dll
