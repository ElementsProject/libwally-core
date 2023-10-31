set LIBWALLY_DIR=%cd%

if "%ELEMENTS_BUILD%" == "elements" (
  set OPTS=/DBUILD_ELEMENTS
) else (
  set OPTS=
)

REM Compile everything (wally, ccan, libsecp256k) in one lump.
cl /utf-8 /DWALLY_CORE_BUILD %OPTS% /I%LIBWALLY_DIR% /I%LIBWALLY_DIR%\src /I%LIBWALLY_DIR%\include /I%LIBWALLY_DIR%\src\ccan /I%LIBWALLY_DIR%\src\ccan\base64 /I%LIBWALLY_DIR%\src\secp256k1 /Zi /LD src/amalgamation/combined.c src/amalgamation/combined_ccan.c src/amalgamation/combined_ccan2.c /Fewally.dll
