#ifndef CORE_LIBS_PRX_LIBC_INCLUDE_APPLICATIONGUESTPLATFORM_HPP
#define CORE_LIBS_PRX_LIBC_INCLUDE_APPLICATIONGUESTPLATFORM_HPP

#include <cstdint>

enum class GuestPlatform : std::uint32_t {
    Ps4 = 4,
    Ps5 = 5
};

extern "C" {

GuestPlatform ApplicationGuestPlatform_nid_no_patch();

}

#endif
