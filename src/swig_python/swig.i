%module wallycore
%{
#define SWIG_FILE_WITH_INIT
#include <stdbool.h>
#include "../include/wally-core.h"
#include "../include/wally_bip39.h"
#include "../include/wally_bip32.h"
%}

%include pybuffer.i
%include cstring.i
%pybuffer_binary(const unsigned char *bytes_in, size_t len);
%pybuffer_mutable_binary(unsigned char *bytes_in_out, size_t len);
%pybuffer_mutable_binary(unsigned char *bytes_out, size_t len);
%cstring_output_allocate(char **output, wally_free_string(*$1));

%include "../include/wally-core.h"
%include "../include/wally_bip39.h"
%include "../include/wally_bip32.h"
