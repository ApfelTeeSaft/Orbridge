#ifndef DOMAIN_GUESTPLATFORM_HPP
#define DOMAIN_GUESTPLATFORM_HPP

#include <domain/Types.hpp>
#include <array>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>

namespace Domain {

enum class GuestPlatform {
    Ps4,
    Ps5
};

enum class GuestPlatformSelection {
    Auto,
    Ps4,
    Ps5
};

struct GuestPlatformProfile {
    GuestPlatform Platform;
    std::string_view Name;
    std::int64_t NeededModuleTag;
    bool SceTablesInDynamicData;
    bool LoadsSceRelro;
    bool DropsInterpreter;
    bool DeclaresTextRelocations;
    std::optional<std::uint16_t> ExecutableType;
};

inline constexpr std::array<GuestPlatformProfile, 2> GuestPlatformProfiles{{
    {GuestPlatform::Ps4, "PS4", 0x6100000f, true, true, true, true, 0xfe10},
    {GuestPlatform::Ps5, "PS5", 0x61000045, false, false, false, false, std::nullopt},
}};

struct GuestPlatformTag {
    std::int64_t Tag;
    GuestPlatform Platform;
    std::string_view Name;
};

inline constexpr std::array<GuestPlatformTag, 7> GuestPlatformTags{{
    {0x6100000d, GuestPlatform::Ps4, "DT_SCE_MODULE_INFO"},
    {0x6100000f, GuestPlatform::Ps4, "DT_SCE_NEEDED_MODULE"},
    {0x61000013, GuestPlatform::Ps4, "DT_SCE_EXPORT_LIB"},
    {0x61000015, GuestPlatform::Ps4, "DT_SCE_IMPORT_LIB"},
    {0x61000043, GuestPlatform::Ps5, "DT_SCE_MODULE_INFO"},
    {0x61000045, GuestPlatform::Ps5, "DT_SCE_NEEDED_MODULE"},
    {0x61000049, GuestPlatform::Ps5, "DT_SCE_IMPORT_LIB"},
}};

struct GuestPlatformDetection {
    GuestPlatform Platform;
    std::optional<GuestPlatformTag> Evidence;
    bool Selected;
};

inline const GuestPlatformProfile& PlatformProfile(const GuestPlatform platform) {
    for (const auto& profile : GuestPlatformProfiles)
        if (profile.Platform == platform) return profile;
    throw RelinkerException("Unknown guest platform");
}

inline std::string PlatformName(const GuestPlatform platform) {
    return std::string(PlatformProfile(platform).Name);
}

inline std::string DescribeTag(const GuestPlatformTag& tag) {
    std::ostringstream text;
    text << tag.Name << " 0x" << std::hex << tag.Tag;
    return text.str();
}

inline std::optional<GuestPlatformTag> FindGuestPlatformTag(const std::int64_t tag) {
    for (const auto& known : GuestPlatformTags)
        if (known.Tag == tag) return known;
    return std::nullopt;
}

inline std::optional<GuestPlatformTag> GuestPlatformEvidence(std::span<const std::int64_t> tags, const std::string& subject) {
    std::optional<GuestPlatformTag> ps4;
    std::optional<GuestPlatformTag> ps5;
    for (const auto tag : tags) {
        const auto known = FindGuestPlatformTag(tag);
        if (!known) continue;
        auto& first = known->Platform == GuestPlatform::Ps4 ? ps4 : ps5;
        if (!first) first = known;
    }
    if (ps4 && ps5)
        throw RelinkerException(subject + ": conflicting PS4 (" + DescribeTag(*ps4) + ") and PS5 (" + DescribeTag(*ps5) + ") module metadata");
    return ps4 ? ps4 : ps5;
}

inline GuestPlatformDetection SelectGuestPlatform(const std::optional<GuestPlatformTag>& evidence, const GuestPlatformSelection selection, const std::string& subject) {
    if (selection == GuestPlatformSelection::Auto) {
        if (evidence) return {evidence->Platform, evidence, false};
        return {GuestPlatform::Ps5, std::nullopt, false};
    }
    const auto selected = selection == GuestPlatformSelection::Ps4 ? GuestPlatform::Ps4 : GuestPlatform::Ps5;
    if (evidence && evidence->Platform != selected)
        throw RelinkerException("--platform " + std::string(selected == GuestPlatform::Ps4 ? "ps4" : "ps5") + " conflicts with " + PlatformName(evidence->Platform) + " module metadata (" + DescribeTag(*evidence) + ") in " + subject);
    return {selected, evidence, true};
}

inline std::string DescribeGuestPlatform(const GuestPlatformDetection& detection) {
    if (detection.Evidence) return "Detected guest platform: " + PlatformName(detection.Platform) + " (" + DescribeTag(*detection.Evidence) + ")";
    if (detection.Selected) return "Guest platform: " + PlatformName(detection.Platform) + " (--platform; no SCE module or library tags)";
    return "Guest platform: " + PlatformName(detection.Platform) + " (no SCE module or library tags; default)";
}

inline void RequireGuestPlatform(const std::optional<GuestPlatformTag>& evidence, const GuestPlatform platform, const std::string& subject) {
    if (evidence && evidence->Platform != platform)
        throw RelinkerException(subject + " carries " + PlatformName(evidence->Platform) + " module metadata (" + DescribeTag(*evidence) + "), but the executable is " + PlatformName(platform));
}

}

#endif
