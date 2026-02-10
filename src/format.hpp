#pragma once

#include <cstdlib>
#include "argmap.hpp"

namespace fs {
    extern size_t get_drives(const ArgMap* argv, size_t argc);
    extern size_t get_volumes(const ArgMap* argv, size_t argc);
}
