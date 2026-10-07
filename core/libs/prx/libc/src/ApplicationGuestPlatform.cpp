#include "prx/libc/include/ApplicationGuestPlatform.hpp"
#include <cstring>
#include <stdexcept>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#elif defined(__linux__)
#include "prx/libc/include/specifics/linux/ElfTypes.hpp"
#endif

namespace {

GuestPlatform requirePlatform(const std::uint64_t value) {
    if (value != static_cast<std::uint32_t>(GuestPlatform::Ps4) && value != static_cast<std::uint32_t>(GuestPlatform::Ps5))
        throw std::runtime_error("guest platform: invalid platform marker in the executable");
    return static_cast<GuestPlatform>(value);
}

GuestPlatform readGuestPlatform() {
#ifdef _WIN32
    const auto* image = reinterpret_cast<const std::byte*>(GetModuleHandleW(nullptr));
    if (image == nullptr) throw std::runtime_error("guest platform: main image is unavailable");
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) throw std::runtime_error("guest platform: invalid DOS header");
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) throw std::runtime_error("guest platform: invalid PE header");
    const auto* sections = IMAGE_FIRST_SECTION(nt);
    const auto imageSize = nt->OptionalHeader.SizeOfImage;
    bool found = false;
    std::uint32_t value = 0;
    for (unsigned index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
        const auto& section = sections[index];
        if (std::memcmp(section.Name, ".gplat\0\0", 8) != 0) continue;
        if (found) throw std::runtime_error("guest platform: duplicate platform marker");
        if (section.Misc.VirtualSize != 4 || section.VirtualAddress > imageSize || 4 > imageSize - section.VirtualAddress) throw std::runtime_error("guest platform: invalid platform marker section");
        std::memcpy(&value, image + section.VirtualAddress, sizeof(value));
        found = true;
    }
    if (!found) throw std::runtime_error("guest platform: the executable has no platform marker; relink it");
    return requirePlatform(value);
#elif defined(__linux__)
    constexpr std::uint32_t dynamicSegment = 2;
    constexpr std::int64_t platformTag = 0x6f726200;
    struct Search {
        std::uint64_t value = 0;
        bool found = false;
        bool duplicate = false;
    } search;
    dl_iterate_phdr([](dl_phdr_info* image, std::size_t, void* data) {
        auto& result = *static_cast<Search*>(data);
        if (image->dlpi_name != nullptr && image->dlpi_name[0] != '\0') return 0;
        for (std::uint16_t index = 0; index < image->dlpi_phnum; ++index) {
            const auto& header = image->dlpi_phdr[index];
            if (header.p_type != dynamicSegment) continue;
            const auto* entries = reinterpret_cast<const std::int64_t*>(image->dlpi_addr + header.p_vaddr);
            for (std::uint64_t entry = 0; (entry + 1) * 16 <= header.p_memsz && entries[entry * 2] != 0; ++entry) {
                if (entries[entry * 2] != platformTag) continue;
                if (result.found) result.duplicate = true;
                result.found = true;
                result.value = static_cast<std::uint64_t>(entries[entry * 2 + 1]);
            }
        }
        return 1;
    }, &search);
    if (search.duplicate) throw std::runtime_error("guest platform: duplicate platform marker");
    if (!search.found) throw std::runtime_error("guest platform: the executable has no platform marker; relink it");
    return requirePlatform(search.value);
#else
    throw std::runtime_error("guest platform: unsupported executable format");
#endif
}

}

GuestPlatform ApplicationGuestPlatform_nid_no_patch() {
    static const GuestPlatform platform = readGuestPlatform();
    return platform;
}
