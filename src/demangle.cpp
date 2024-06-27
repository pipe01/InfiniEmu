#include "demangle.h"

#include <cxxabi.h>

extern "C"
char *demangle(const char *mangled)
{
    int status;
    return abi::__cxa_demangle(mangled, NULL, NULL, &status);
}
