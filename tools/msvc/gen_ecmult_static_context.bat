cl /utf-8 /DWALLY_CORE_BUILD /DHAVE_CONFIG_H /DSECP256K1_BUILD /I%LIBWALLY_DIR%\src\wrap_js\windows_config /I%LIBWALLY_DIR%\ /I%LIBWALLY_DIR%\src /I%LIBWALLY_DIR%\include /I%LIBWALLY_DIR%\src\ccan /I%LIBWALLY_DIR%\src\secp256k1 /Zi %LIBWALLY_DIR%\src/secp256k1/src/gen_context.c /Fegen_context.exe
gen_context.exe
