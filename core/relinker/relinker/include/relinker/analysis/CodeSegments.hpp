#ifndef RELINKER_ANALYSIS_CODESEGMENTS_HPP
#define RELINKER_ANALYSIS_CODESEGMENTS_HPP

#include <domain/GuestPlatformId.hpp>
#include <domain/Types.hpp>
#include <vector>

namespace Relinker {

std::vector<Domain::ProgramHeader> ReadCodeSegments(const std::vector<std::uint8_t>& bytes, const std::vector<Domain::ProgramHeader>& headers, Domain::GuestPlatform platform);

}

#endif
