%module wallycore
%{
#define SWIG_FILE_WITH_INIT
#include <stdbool.h>
%}
%include "../include/wally-core.h"
%include "../include/wally_bip39.h"
