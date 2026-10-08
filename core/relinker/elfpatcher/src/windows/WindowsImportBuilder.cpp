#include <elfpatcher/windows/WindowsImportBuilder.hpp>
#include <io/BufferUtils.hpp>
#include <set>

namespace Elfpatcher::Windows {

WindowsImports WindowsImportBuilder::Build(const std::uint32_t sectionRva, const bool includeAddressWait) const {
    // WaitOnAddress is imported from its documented API-set contract, not
    // KERNEL32.dll (which is not guaranteed to export this entry point).
    const std::vector<std::string> names = {"ExitProcess", "FormatMessageA", "FreeLibrary", "GetCommandLineW", "GetFileAttributesA", "GetLastError", "GetModuleFileNameA", "GetModuleHandleA", "GetProcAddress", "GetStdHandle", "GetSystemDirectoryA", "LoadLibraryExA", "LocalFree", "RaiseException", "VirtualAlloc", "WideCharToMultiByte", "WriteFile", "lstrcatA", "lstrcmpA", "lstrcmpiA", "lstrcpyA", "lstrlenA"};
    const std::size_t groupCount = includeAddressWait ? 2 : 1;
    const std::size_t descriptorBytes = (groupCount + 1) * 20;
    WindowsImports result{{".idata", sectionRva, SectionRead | SectionWrite | 0x40u,
                           std::vector<std::uint8_t>(descriptorBytes)},
                          {sectionRva, CheckedRva(descriptorBytes)}, {}, {}};
    auto& bytes = result.Section.Data;
    const auto kernelLookup = bytes.size();
    bytes.resize(bytes.size() + (names.size() + 1) * 8);
    const auto waitLookup = bytes.size();
    if (includeAddressWait) bytes.resize(bytes.size() + 2 * 8);
    const auto kernelAddresses = bytes.size();
    bytes.resize(bytes.size() + (names.size() + 1) * 8);
    const auto waitAddresses = bytes.size();
    if (includeAddressWait) bytes.resize(bytes.size() + 2 * 8);
    result.AddressTable = {CheckedRva(sectionRva + kernelAddresses),
                           CheckedRva(bytes.size() - kernelAddresses)};

    const auto addGroup = [&](std::size_t index, const std::string& library,
                              const std::vector<std::string>& symbols,
                              std::size_t lookup, std::size_t addresses) {
        for (std::size_t symbol = 0; symbol < symbols.size(); ++symbol) {
            const auto nameRva = CheckedRva(sectionRva + bytes.size());
            Io::AppendU16(bytes, 0);
            Io::AppendString(bytes, symbols[symbol]);
            Io::AlignBuffer(bytes, 2);
            Io::WriteU64(bytes, lookup + symbol * 8, nameRva);
            Io::WriteU64(bytes, addresses + symbol * 8, nameRva);
            result.Functions.emplace(symbols[symbol], CheckedRva(sectionRva + addresses + symbol * 8));
        }
        const auto libraryRva = CheckedRva(sectionRva + bytes.size());
        Io::AppendString(bytes, library);
        const auto descriptor = index * 20;
        Io::WriteU32(bytes, descriptor, CheckedRva(sectionRva + lookup));
        Io::WriteU32(bytes, descriptor + 12, libraryRva);
        Io::WriteU32(bytes, descriptor + 16, CheckedRva(sectionRva + addresses));
    };
    addGroup(0, "KERNEL32.dll", names, kernelLookup, kernelAddresses);
    if (includeAddressWait)
        addGroup(1, "api-ms-win-core-synch-l1-2-0.dll", {"WaitOnAddress"}, waitLookup, waitAddresses);
    return result;
}

std::vector<std::string> WindowsImportBuilder::ReadLibraries(const Domain::SysVDynamicSection& dynamicSection) const {
    const auto& bytes = dynamicSection.DynamicSegmentData;
    if (bytes.size() % 16 != 0)
        throw Domain::RelinkerException("Invalid dynamic segment size");
    std::vector<std::string> result;
    std::set<std::string> unique;
    for (std::size_t offset = 0; offset < bytes.size(); offset += 16) {
        const auto tag = Io::ReadU64(bytes, offset);
        if (tag != 1)
            throw Domain::RelinkerException("Unexpected tag in rebuilt ELF dependency table", offset);
        const auto nameOffset = Io::ReadU64(bytes, offset + 8);
        if (nameOffset >= dynamicSection.DynStrData.size())
            throw Domain::RelinkerException("DT_NEEDED string offset is out of bounds", nameOffset);
        auto name = ReadString(dynamicSection.DynStrData, static_cast<std::size_t>(nameOffset));
        if (name.empty() || name.find_first_of("/\\:") != std::string::npos || !unique.insert(name).second)
            throw Domain::RelinkerException("Invalid or duplicate DT_NEEDED library: " + name);
        result.push_back(std::move(name));
    }
    // AnyPS5 implements the C runtime in libc.prx. Windows GetProcAddress
    // does not search a module's dependencies as ELF symbol lookup does.
    // Keep the requested module first, then make its shared runtime visible.
    if (unique.contains("libSceLibcInternal.prx") && !unique.contains("libc.prx"))
        result.push_back("libc.prx");
    return result;
}

}
