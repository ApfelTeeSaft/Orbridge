#include <domain/GuestPlatform.hpp>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using Domain::GuestPlatform;
using Domain::GuestPlatformSelection;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void requireFailure(const std::function<void()>& operation, const std::string& expected, const char* message) {
    try {
        operation();
    } catch (const Domain::RelinkerException& error) {
        if (std::string(error.what()).find(expected) == std::string::npos) throw std::runtime_error(std::string(message) + ": " + error.what());
        return;
    }
    throw std::runtime_error(message);
}

void evidenceFromModuleTags() {
    const std::vector<std::int64_t> ps4{1, 0x61000035, 0x6100000f, 0x61000015};
    const auto ps4Evidence = Domain::GuestPlatformEvidence(ps4, "ps4");
    require(ps4Evidence && ps4Evidence->Platform == GuestPlatform::Ps4 && ps4Evidence->Tag == 0x6100000f, "PS4 needed module tag was not detected");
    for (const std::int64_t tag : {0x6100000d, 0x61000013, 0x61000015}) {
        const std::vector<std::int64_t> tags{tag};
        require(Domain::GuestPlatformEvidence(tags, "ps4")->Platform == GuestPlatform::Ps4, "PS4 module or library tag was not detected");
    }
    for (const std::int64_t tag : {0x61000043, 0x61000045, 0x61000049}) {
        const std::vector<std::int64_t> tags{5, tag};
        require(Domain::GuestPlatformEvidence(tags, "ps5")->Platform == GuestPlatform::Ps5, "PS5 module or library tag was not detected");
    }
}

void sharedTagsAreNoEvidence() {
    const std::vector<std::int64_t> shared{1, 5, 6, 0x61000007, 0x61000017, 0x61000019, 0x61000027, 0x61000035, 0x6100003f, 0x6fffff01};
    require(!Domain::GuestPlatformEvidence(shared, "shared"), "A tag both platforms use was taken as platform evidence");
}

void conflictingEvidenceFails() {
    const std::vector<std::int64_t> mixed{0x61000045, 0x6100000f};
    requireFailure([&] { (void)Domain::GuestPlatformEvidence(mixed, "mixed.elf"); }, "mixed.elf: conflicting PS4 (DT_SCE_NEEDED_MODULE 0x6100000f) and PS5 (DT_SCE_NEEDED_MODULE 0x61000045)", "Conflicting module metadata was accepted");
}

void selection() {
    const auto ps4 = Domain::FindGuestPlatformTag(0x6100000f);
    const auto ps5 = Domain::FindGuestPlatformTag(0x61000045);
    const auto detected = Domain::SelectGuestPlatform(ps4, GuestPlatformSelection::Auto, "input");
    require(detected.Platform == GuestPlatform::Ps4 && detected.Evidence && !detected.Selected, "Auto did not follow the metadata");
    require(Domain::DescribeGuestPlatform(detected) == "Detected guest platform: PS4 (DT_SCE_NEEDED_MODULE 0x6100000f)", "Unexpected detection diagnostic");
    require(Domain::SelectGuestPlatform(ps5, GuestPlatformSelection::Ps5, "input").Platform == GuestPlatform::Ps5, "A matching selection was rejected");
    requireFailure([&] { (void)Domain::SelectGuestPlatform(ps5, GuestPlatformSelection::Ps4, "input"); }, "--platform ps4 conflicts with PS5 module metadata (DT_SCE_NEEDED_MODULE 0x61000045) in input", "A conflicting selection was accepted");
    requireFailure([&] { (void)Domain::SelectGuestPlatform(ps4, GuestPlatformSelection::Ps5, "input"); }, "--platform ps5 conflicts with PS4", "A conflicting selection was accepted");
    const auto selected = Domain::SelectGuestPlatform(std::nullopt, GuestPlatformSelection::Ps4, "input");
    require(selected.Platform == GuestPlatform::Ps4 && selected.Selected && !selected.Evidence, "A selection without metadata was ignored");
    require(Domain::DescribeGuestPlatform(selected) == "Guest platform: PS4 (--platform; no SCE module or library tags)", "Unexpected selection diagnostic");
    const auto fallback = Domain::SelectGuestPlatform(std::nullopt, GuestPlatformSelection::Auto, "input");
    require(fallback.Platform == GuestPlatform::Ps5 && !fallback.Selected && !fallback.Evidence, "Executables without metadata no longer keep the PS5 default");
    require(Domain::DescribeGuestPlatform(fallback) == "Guest platform: PS5 (no SCE module or library tags; default)", "Unexpected default diagnostic");
}

void modulePlatform() {
    Domain::RequireGuestPlatform(std::nullopt, GuestPlatform::Ps4, "Guest module a.prx");
    Domain::RequireGuestPlatform(Domain::FindGuestPlatformTag(0x6100000d), GuestPlatform::Ps4, "Guest module a.prx");
    requireFailure([] { Domain::RequireGuestPlatform(Domain::FindGuestPlatformTag(0x6100000f), GuestPlatform::Ps5, "Guest module a.prx"); }, "Guest module a.prx carries PS4 module metadata (DT_SCE_NEEDED_MODULE 0x6100000f), but the executable is PS5", "A module of the other platform was accepted");
}

void profiles() {
    require(Domain::PlatformProfile(GuestPlatform::Ps4).NeededModuleTag == 0x6100000f, "Unexpected PS4 needed module tag");
    require(Domain::PlatformProfile(GuestPlatform::Ps5).NeededModuleTag == 0x61000045, "Unexpected PS5 needed module tag");
    const auto& ps4 = Domain::PlatformProfile(GuestPlatform::Ps4);
    require(ps4.SceTablesInDynamicData && ps4.LoadsSceRelro && ps4.DropsInterpreter && ps4.DeclaresTextRelocations && ps4.CodeSharesSegmentWithReadOnlyData && ps4.ZeroInitFiniIsFunction && ps4.ResolvesGuestImportsByModule && ps4.ExecutableType == 0xfe10, "Unexpected PS4 format traits");
    const auto& ps5 = Domain::PlatformProfile(GuestPlatform::Ps5);
    require(!ps5.SceTablesInDynamicData && !ps5.LoadsSceRelro && !ps5.DropsInterpreter && !ps5.DeclaresTextRelocations && !ps5.CodeSharesSegmentWithReadOnlyData && !ps5.ZeroInitFiniIsFunction && !ps5.ResolvesGuestImportsByModule && !ps5.ExecutableType, "The PS5 format traits changed");
    require(Domain::PlatformName(GuestPlatform::Ps4) == "PS4" && Domain::PlatformName(GuestPlatform::Ps5) == "PS5", "Unexpected platform names");
}

}

int main() {
    try {
        evidenceFromModuleTags();
        sharedTagsAreNoEvidence();
        conflictingEvidenceFails();
        selection();
        modulePlatform();
        profiles();
        std::cout << "Guest platform tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
