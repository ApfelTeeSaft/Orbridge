#include <relinker/analysis/CodeSegments.hpp>
#include <relinker/analysis/UnusedNidFilter/EhFrameReader.hpp>
#include <codegen/CodegenException.hpp>
#include <codegen/x86/X64InstructionDecoder.hpp>
#include <domain/GuestPlatform.hpp>
#include <io/BufferUtils.hpp>
#include <algorithm>
#include <initializer_list>
#include <map>
#include <optional>
#include <string>

namespace Relinker {

namespace {

constexpr std::uint32_t PtLoad = 1;
constexpr std::uint32_t PtDynamic = 2;
constexpr std::uint32_t PtSceDynlibData = 0x61000000;
constexpr std::uint32_t PtSceRelro = 0x61000010;
constexpr std::uint32_t PfExecute = 1;
constexpr std::int64_t DtInit = 12;
constexpr std::int64_t DtFini = 13;
constexpr std::int64_t DtSceJmpRel = 0x61000029;
constexpr std::int64_t DtScePltRelSize = 0x6100002d;
constexpr std::uint32_t RelocationJumpSlot = 7;
constexpr std::uint64_t PltStubSize = 16;
constexpr std::uint64_t PltPushOffset = 6;

struct CodeRange {
    std::uint64_t Begin;
    std::uint64_t End;
};

class CodeLayout {
public:
    CodeLayout(const std::vector<std::uint8_t>& bytes, const std::vector<Domain::ProgramHeader>& headers) : bytes(bytes) {
        for (auto header : headers) {
            if (header.Type == PtSceRelro) header.Type = PtLoad;
            mapped.push_back(header);
        }
        readDynamicTags();
    }

    std::vector<CodeRange> Ranges() {
        std::vector<CodeRange> ranges;
        for (const auto& function : UnusedNidFilter::ReadExceptionFunctions(bytes, mapped, {}, {}))
            ranges.push_back({function.Begin, function.End});
        addPlt(ranges);
        std::vector<std::uint64_t> roots;
        if (const auto entry = Io::ReadU64(bytes, 24); entry != 0) roots.push_back(entry);
        for (const auto tag : {DtInit, DtFini})
            if (const auto found = tags.find(tag); found != tags.end()) roots.push_back(found->second);
        std::sort(ranges.begin(), ranges.end(), [](const CodeRange& left, const CodeRange& right) { return left.Begin < right.Begin; });
        std::vector<CodeRange> functions;
        for (const auto root : roots) {
            const auto next = std::upper_bound(ranges.begin(), ranges.end(), root, [](std::uint64_t address, const CodeRange& range) { return address < range.Begin; });
            if (next != ranges.begin() && root < std::prev(next)->End) continue;
            functions.push_back(function(root, next == ranges.end() ? std::nullopt : std::optional(next->Begin)));
        }
        ranges.insert(ranges.end(), functions.begin(), functions.end());
        return ranges;
    }

    const Domain::ProgramHeader* ExecutableSegment(const std::uint64_t address) const {
        for (const auto& header : mapped)
            if (header.Type == PtLoad && (header.Flags & PfExecute) != 0 && address >= header.MappedAddress && address - header.MappedAddress < header.FileSize)
                return &header;
        return nullptr;
    }

private:
    const std::vector<std::uint8_t>& bytes;
    std::vector<Domain::ProgramHeader> mapped;
    std::map<std::int64_t, std::uint64_t> tags;

    void readDynamicTags() {
        for (const auto& header : mapped) {
            if (header.Type != PtDynamic) continue;
            if (header.Offset > bytes.size() || header.FileSize > bytes.size() - header.Offset)
                throw Domain::RelinkerException("Code analysis: dynamic segment exceeds the file", header.Offset);
            for (std::uint64_t offset = 0; offset + 16 <= header.FileSize; offset += 16) {
                const auto tag = static_cast<std::int64_t>(Io::ReadU64(bytes, header.Offset + offset));
                if (tag == 0) break;
                tags.emplace(tag, Io::ReadU64(bytes, header.Offset + offset + 8));
            }
            return;
        }
    }

    std::optional<std::uint64_t> fileOffset(const std::uint64_t address, const std::uint64_t size) const {
        for (const auto& header : mapped) {
            if (header.Type != PtLoad || address < header.MappedAddress || address - header.MappedAddress > header.FileSize || size > header.FileSize - (address - header.MappedAddress)) continue;
            const auto offset = header.Offset + (address - header.MappedAddress);
            if (offset > bytes.size() || size > bytes.size() - offset) return std::nullopt;
            return offset;
        }
        return std::nullopt;
    }

    bool hasBytes(const std::uint64_t address, std::initializer_list<std::uint8_t> expected) const {
        const auto* segment = ExecutableSegment(address);
        if (segment == nullptr || expected.size() > segment->FileSize - (address - segment->MappedAddress)) return false;
        const auto offset = segment->Offset + (address - segment->MappedAddress);
        return std::equal(expected.begin(), expected.end(), bytes.begin() + static_cast<std::ptrdiff_t>(offset));
    }

    void addPlt(std::vector<CodeRange>& ranges) const {
        const auto table = tags.find(DtSceJmpRel);
        const auto size = tags.find(DtScePltRelSize);
        if (table == tags.end() || size == tags.end() || size->second == 0) return;
        const Domain::ProgramHeader* data = nullptr;
        for (const auto& header : mapped)
            if (header.Type == PtSceDynlibData) data = &header;
        if (data == nullptr || size->second % 24 != 0 || table->second > data->FileSize || size->second > data->FileSize - table->second || data->Offset + data->FileSize > bytes.size())
            throw Domain::RelinkerException("Code analysis: SCE DT_JMPREL lies outside PT_SCE_DYNLIBDATA", table->second);
        for (std::uint64_t entry = data->Offset + table->second; entry < data->Offset + table->second + size->second; entry += 24) {
            if (static_cast<std::uint32_t>(Io::ReadU64(bytes, entry + 8)) != RelocationJumpSlot) continue;
            const auto slot = Io::ReadU64(bytes, entry);
            const auto slotOffset = fileOffset(slot, 8);
            if (!slotOffset) throw Domain::RelinkerException("Code analysis: PLT slot is not file-backed", slot);
            const auto push = Io::ReadU64(bytes, *slotOffset);
            if (push == 0) continue;
            if (push < PltPushOffset || !hasBytes(push - PltPushOffset, {0xff, 0x25}) || !hasBytes(push, {0x68}) || !hasBytes(push + 5, {0xe9}))
                throw Domain::RelinkerException("Code analysis: PLT slot does not hold the address of a lazy-binding stub", slot);
            ranges.push_back({push - PltPushOffset, push - PltPushOffset + PltStubSize});
            const auto segment = ExecutableSegment(push + 6);
            const auto displacement = static_cast<std::int32_t>(Io::ReadU32(bytes, segment->Offset + (push + 6 - segment->MappedAddress)));
            const auto resolver = push + 10 + static_cast<std::uint64_t>(static_cast<std::int64_t>(displacement));
            if (!hasBytes(resolver, {0xff, 0x35}) || !hasBytes(resolver + 6, {0xff, 0x25}))
                throw Domain::RelinkerException("Code analysis: PLT stub does not branch to the PLT resolver entry", push - PltPushOffset);
            ranges.push_back({resolver, resolver + PltStubSize});
        }
    }

    CodeRange function(const std::uint64_t begin, const std::optional<std::uint64_t> following) const {
        const auto* segment = ExecutableSegment(begin);
        if (segment == nullptr) throw Domain::RelinkerException("Code analysis: function lies outside the executable segments", begin);
        const auto segmentEnd = segment->MappedAddress + segment->FileSize;
        const auto limit = following ? std::min(*following, segmentEnd) : segmentEnd;
        const Codegen::X64InstructionDecoder decoder;
        auto furthest = begin;
        auto address = begin;
        while (address < limit) {
            Codegen::DecodedInstructionInfo info{};
            try {
                info = decoder.DecodeInstruction(bytes.data() + segment->Offset + (address - segment->MappedAddress), segmentEnd - address);
            } catch (const Codegen::CodegenException& error) {
                throw Domain::RelinkerException(std::string("Code analysis: ") + error.what(), address);
            }
            if (info.Length == 0) throw Domain::RelinkerException("Code analysis: empty instruction", address);
            const auto next = address + info.Length;
            const bool jump = info.FlowKind == Codegen::ControlFlowKind::ConditionalBranch || info.FlowKind == Codegen::ControlFlowKind::UnconditionalJump;
            if (jump && info.HasBranchTarget && !info.HasRipRelativeDisp) {
                const auto target = next + static_cast<std::uint64_t>(info.BranchDisp);
                if (target > furthest && target < limit) furthest = target;
            }
            const bool terminal = info.FlowKind == Codegen::ControlFlowKind::Return || info.FlowKind == Codegen::ControlFlowKind::UnconditionalJump
                || info.FlowKind == Codegen::ControlFlowKind::IndirectJump || info.FlowKind == Codegen::ControlFlowKind::Trap;
            if (terminal && next > furthest) return {begin, next};
            address = next;
        }
        if (following && address >= *following) return {begin, *following};
        throw Domain::RelinkerException("Code analysis: function does not end within its executable segment", begin);
    }
};

}

std::vector<Domain::ProgramHeader> ReadCodeSegments(const std::vector<std::uint8_t>& bytes, const std::vector<Domain::ProgramHeader>& headers, const Domain::GuestPlatform platform) {
    std::vector<Domain::ProgramHeader> segments;
    for (const auto& header : headers)
        if (header.Type == PtLoad && (header.Flags & PfExecute) != 0) segments.push_back(header);
    if (!Domain::PlatformProfile(platform).CodeSharesSegmentWithReadOnlyData) return segments;
    CodeLayout layout(bytes, headers);
    std::map<std::uint64_t, CodeRange> extents;
    for (const auto& range : layout.Ranges()) {
        const auto* segment = layout.ExecutableSegment(range.Begin);
        if (segment == nullptr || range.End <= range.Begin || range.End - segment->MappedAddress > segment->FileSize)
            throw Domain::RelinkerException("Code analysis: code range lies outside the executable segments", range.Begin);
        const auto [extent, inserted] = extents.emplace(segment->MappedAddress, range);
        extent->second.Begin = std::min(extent->second.Begin, range.Begin);
        extent->second.End = std::max(extent->second.End, range.End);
    }
    for (auto& segment : segments) {
        const auto extent = extents.find(segment.MappedAddress);
        if (segment.FileSize == 0 || extent == extents.end()) continue;
        segment.Offset += extent->second.Begin - segment.MappedAddress;
        segment.PhysicalAddress += extent->second.Begin - segment.MappedAddress;
        segment.MappedAddress = extent->second.Begin;
        segment.FileSize = extent->second.End - extent->second.Begin;
        segment.MemorySize = segment.FileSize;
    }
    return segments;
}

}
