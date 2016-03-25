%module wallycore
%{
#define SWIG_FILE_WITH_INIT
#include <stdbool.h>
#include "../include/wally-core.h"
#include "../include/wally_bip39.h"
%}

#ifdef SWIGPYTHON
%include pybuffer.i
%pybuffer_binary(const unsigned char *bytes, size_t len);
%pybuffer_mutable_binary(unsigned char *bytes, size_t len);
#endif

%include "../include/wally-core.h"
%include "../include/wally_bip39.h"
