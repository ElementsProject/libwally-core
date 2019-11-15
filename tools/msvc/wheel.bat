REM Run swig to generate the wrapper source files required by
REM setup.py build step
call "%~dp0"\swig.bat || echo ERRORSWIG && exit /b 1

REM Set VS 2017 environment
call "C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\Common7\Tools\VsDevCmd.bat"

REM Need to first build gen_context.exe to generate a header file
REM It seems possible to skip this step and remove the definition
REM of USE_ECMULT_STATIC_PRECOMPUTATION  from the compiler flags
set LIBWALLY_DIR=%cd%
call "%~dp0\gen_ecmult_static_context.bat" || echo ERRORGENCONTEXT && exit /b 1

REM Install virtualenv - this should possibly be on the CI box
python -m pip install virtualenv

REM Create a new venv and install wheel required for building wheels
rmdir /s /q venv
python -m virtualenv venv
venv\Scripts\pip install wheel || echo ERRORWHEEL && exit /b 1

REM Build the wheel
mkdir wally_dist
venv\Scripts\pip wheel --wheel-dir=wally_dist . || echo ERRORPACK && exit /b 1

REM smoketest: create a new venv, install the wheel we just created and
REM check it works
rmdir /s /q venv-smoketest
python -m virtualenv venv-smoketest
venv-smoketest\Scripts\pip install --find-links=.\wally_dist wallycore
venv-smoketest\Scripts\python -c "import wallycore as wally; assert wally.hex_from_bytes(wally.hex_to_bytes('ff')) == 'ff'" || echo ERRORSMOKE && exit /b 1
