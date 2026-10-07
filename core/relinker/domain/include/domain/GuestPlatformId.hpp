#ifndef DOMAIN_GUESTPLATFORMID_HPP
#define DOMAIN_GUESTPLATFORMID_HPP

#include <cstdint>

namespace Domain {

enum class GuestPlatform : std::uint32_t {
    Ps4 = 4,
    Ps5 = 5
};

}

#endif
