#include "GcnDecoder/GcnInstructionDecoder.hpp"
#include "GcnDecoder/GcnOpcodeTable.hpp"
#include "RdnaDecoder/RdnaInstructionDecoder.hpp"
#include "RdnaDecoder/RdnaOpcode.hpp"
#include <algorithm>
#include <array>
#include <cstdio>
#include <stdexcept>
#include <string>

namespace ShaderRecompiler {

namespace {

constexpr std::uint32_t literalCode = 255u;
constexpr std::uint32_t rdnaVop3Encoding = 0x35u;
constexpr std::uint32_t rdnaSmemEncoding = 0x3du;
constexpr std::uint32_t rdnaNullScalarRegister = 0x7du;
constexpr std::uint32_t smrdLiteralOffset = 0xffu;
constexpr std::uint32_t scalarRegisterCount = 104u;

enum class GcnEncoding {
    Sop2,
    Sopk,
    Sop1,
    Sopc,
    Sopp,
    Smrd,
    Vop1,
    Vop2,
    Vopc,
    Vop3,
    Vintrp,
    Ds,
    Flat,
    Mubuf,
    Mtbuf,
    Mimg,
    Exp,
    Unknown
};

std::string toHexString(std::uint32_t value) {
    char buffer[11];
    std::snprintf(buffer, sizeof(buffer), "0x%08x", value);
    return std::string(buffer);
}

[[noreturn]] void reject(std::uint32_t programCounter, std::uint32_t word, const std::string& reason) {
    throw std::invalid_argument("gfx7 " + reason + " at program counter " + toHexString(programCounter) + " raw word " + toHexString(word));
}

GcnEncoding classify(std::uint32_t word) {
    if ((word & 0x80000000u) == 0u) {
        switch ((word >> 25u) & 0x3fu) {
            case 0x3eu: return GcnEncoding::Vopc;
            case 0x3fu: return GcnEncoding::Vop1;
            default: return GcnEncoding::Vop2;
        }
    }
    if ((word & 0xc0000000u) == 0x80000000u) {
        const std::uint32_t opcode = (word >> 23u) & 0x7fu;
        switch (opcode) {
            case 0x7du: return GcnEncoding::Sop1;
            case 0x7eu: return GcnEncoding::Sopc;
            case 0x7fu: return GcnEncoding::Sopp;
            default: return opcode >= 0x60u ? GcnEncoding::Sopk : GcnEncoding::Sop2;
        }
    }
    if ((word >> 27u) == 0x18u) return GcnEncoding::Smrd;
    switch (word >> 26u) {
        case 0x32u: return GcnEncoding::Vintrp;
        case 0x34u: return GcnEncoding::Vop3;
        case 0x36u: return GcnEncoding::Ds;
        case 0x37u: return GcnEncoding::Flat;
        case 0x38u: return GcnEncoding::Mubuf;
        case 0x3au: return GcnEncoding::Mtbuf;
        case 0x3cu: return GcnEncoding::Mimg;
        case 0x3eu: return GcnEncoding::Exp;
        default: return GcnEncoding::Unknown;
    }
}

bool isScalarRegisterCode(std::uint32_t code) {
    return code < scalarRegisterCount || code == 106u || code == 107u || code == 124u || code == 126u || code == 127u;
}

bool isScalarSourceCode(std::uint32_t code, bool literal) {
    return isScalarRegisterCode(code) || (code >= 128u && code <= 208u) || (code >= 240u && code <= 247u) ||
        (code >= 251u && code <= 253u) || (literal && code == literalCode);
}

bool isVectorSourceCode(std::uint32_t code, bool literal) {
    return code >= 256u || isScalarSourceCode(code, literal);
}

void requireScalarRegister(std::uint32_t code, const char* field, std::uint32_t programCounter, std::uint32_t word) {
    if (!isScalarRegisterCode(code)) reject(programCounter, word, std::string(field) + " operand code " + std::to_string(code) + " is not supported");
}

void requireScalarSource(std::uint32_t code, bool literal, const char* field, std::uint32_t programCounter, std::uint32_t word) {
    if (!isScalarSourceCode(code, literal)) reject(programCounter, word, std::string(field) + " operand code " + std::to_string(code) + " is not supported");
}

void requireVectorSource(std::uint32_t code, bool literal, const char* field, std::uint32_t programCounter, std::uint32_t word) {
    if (!isVectorSourceCode(code, literal)) reject(programCounter, word, std::string(field) + " operand code " + std::to_string(code) + " is not supported");
}

const GcnOpcode& requireOpcode(GcnOpcodeFamily family, std::uint32_t opcode, const char* encoding, std::uint32_t programCounter, std::uint32_t word) {
    const auto* entry = FindGcnOpcode(family, opcode);
    if (entry == nullptr) reject(programCounter, word, std::string(encoding) + " opcode " + toHexString(opcode) + " is not supported");
    return *entry;
}

std::uint32_t replaceField(std::uint32_t word, std::uint32_t shift, std::uint32_t mask, std::uint32_t value) {
    return (word & ~(mask << shift)) | (value << shift);
}

std::uint32_t convertWaitcnt(std::uint32_t immediate, std::uint32_t programCounter, std::uint32_t word) {
    if ((immediate & 0xf080u) != 0u) reject(programCounter, word, "s_waitcnt reserved bits are set");
    const std::uint32_t vectorMemory = immediate & 0xfu;
    const std::uint32_t exportCount = (immediate >> 4u) & 0x7u;
    const std::uint32_t scalarMemory = (immediate >> 8u) & 0xfu;
    const std::uint32_t rdnaVectorMemory = vectorMemory == 0xfu ? 0x3fu : vectorMemory;
    const std::uint32_t rdnaScalarMemory = scalarMemory == 0xfu ? 0x3fu : scalarMemory;
    return (rdnaVectorMemory & 0xfu) | (exportCount << 4u) | (rdnaScalarMemory << 8u) | ((rdnaVectorMemory >> 4u) << 14u);
}

RdnaInstruction decodeRewritten(std::uint32_t programCounter, std::span<const std::uint32_t> code, std::uint32_t wordIndex,
                                std::span<const std::uint32_t> rewritten, std::uint32_t originalWords, bool literal) {
    std::array<std::uint32_t, 3> buffer{};
    std::copy(rewritten.begin(), rewritten.end(), buffer.begin());
    std::size_t available = rewritten.size();
    if (literal && wordIndex + originalWords < code.size()) buffer[available++] = code[wordIndex + originalWords];
    auto instruction = DecodeRdnaInstruction(programCounter, std::span<const std::uint32_t>(buffer.data(), available), 0);
    const std::uint32_t usedLiteral = instruction.wordCount > rewritten.size() ? instruction.wordCount - static_cast<std::uint32_t>(rewritten.size()) : 0u;
    instruction.wordCount = originalWords + usedLiteral;
    SetRdnaRawWords(instruction, code, wordIndex, instruction.wordCount);
    return instruction;
}

RdnaInstruction decodeScalar(GcnEncoding encoding, std::uint32_t programCounter, std::span<const std::uint32_t> code, std::uint32_t wordIndex) {
    std::uint32_t word = code[wordIndex];
    switch (encoding) {
        case GcnEncoding::Sop2:
            requireOpcode(GcnOpcodeFamily::Sop2, (word >> 23u) & 0x7fu, "SOP2", programCounter, word);
            requireScalarSource(word & 0xffu, true, "SOP2 ssrc0", programCounter, word);
            requireScalarSource((word >> 8u) & 0xffu, true, "SOP2 ssrc1", programCounter, word);
            requireScalarRegister((word >> 16u) & 0x7fu, "SOP2 sdst", programCounter, word);
            break;
        case GcnEncoding::Sopk:
            requireOpcode(GcnOpcodeFamily::Sopk, (word >> 23u) & 0x1fu, "SOPK", programCounter, word);
            requireScalarRegister((word >> 16u) & 0x7fu, "SOPK sdst", programCounter, word);
            break;
        case GcnEncoding::Sop1:
            requireOpcode(GcnOpcodeFamily::Sop1, (word >> 8u) & 0xffu, "SOP1", programCounter, word);
            requireScalarSource(word & 0xffu, true, "SOP1 ssrc0", programCounter, word);
            requireScalarRegister((word >> 16u) & 0x7fu, "SOP1 sdst", programCounter, word);
            break;
        case GcnEncoding::Sopc:
            requireOpcode(GcnOpcodeFamily::Sopc, (word >> 16u) & 0x7fu, "SOPC", programCounter, word);
            requireScalarSource(word & 0xffu, true, "SOPC ssrc0", programCounter, word);
            requireScalarSource((word >> 8u) & 0xffu, true, "SOPC ssrc1", programCounter, word);
            break;
        case GcnEncoding::Sopp: {
            const auto& entry = requireOpcode(GcnOpcodeFamily::Sopp, (word >> 16u) & 0x7fu, "SOPP", programCounter, word);
            if (entry.name == "s_waitcnt") word = replaceField(word, 0u, 0xffffu, convertWaitcnt(word & 0xffffu, programCounter, word));
            break;
        }
        default:
            throw std::logic_error("scalar decode received a non-scalar encoding");
    }
    const std::array<std::uint32_t, 1> rewritten{word};
    return decodeRewritten(programCounter, code, wordIndex, rewritten, 1u, true);
}

RdnaInstruction decodeVector(GcnEncoding encoding, std::uint32_t programCounter, std::span<const std::uint32_t> code, std::uint32_t wordIndex) {
    std::uint32_t word = code[wordIndex];
    requireVectorSource(word & 0x1ffu, true, "src0", programCounter, word);
    switch (encoding) {
        case GcnEncoding::Vop2: {
            const auto& entry = requireOpcode(GcnOpcodeFamily::Vop2, (word >> 25u) & 0x3fu, "VOP2", programCounter, word);
            word = replaceField(word, 25u, 0x3fu, entry.rdnaOpcode);
            break;
        }
        case GcnEncoding::Vop1: {
            const auto& entry = requireOpcode(GcnOpcodeFamily::Vop1, (word >> 9u) & 0xffu, "VOP1", programCounter, word);
            if (entry.name == "v_readfirstlane_b32") requireScalarRegister((word >> 17u) & 0xffu, "VOP1 sdst", programCounter, word);
            break;
        }
        case GcnEncoding::Vopc:
            requireOpcode(GcnOpcodeFamily::Vopc, (word >> 17u) & 0xffu, "VOPC", programCounter, word);
            break;
        default:
            throw std::logic_error("vector decode received a non-vector encoding");
    }
    const std::array<std::uint32_t, 1> rewritten{word};
    return decodeRewritten(programCounter, code, wordIndex, rewritten, 1u, true);
}

void requireTwoWords(std::span<const std::uint32_t> code, std::uint32_t wordIndex, const char* encoding) {
    if (wordIndex + 1u >= code.size()) throw std::out_of_range(std::string("truncated gfx7 ") + encoding + " instruction");
}

RdnaInstruction decodeVop3(std::uint32_t programCounter, std::span<const std::uint32_t> code, std::uint32_t wordIndex) {
    requireTwoWords(code, wordIndex, "VOP3");
    const std::uint32_t word0 = code[wordIndex];
    const std::uint32_t word1 = code[wordIndex + 1u];
    const std::uint32_t opcode = (word0 >> 17u) & 0x1ffu;
    const auto* entry = FindGcnVop3Opcode(opcode);
    if (entry == nullptr) reject(programCounter, word0, "VOP3 opcode " + toHexString(opcode) + " is not supported");
    std::uint32_t low = 0;
    if (entry->carryOut) {
        if (((word0 >> 15u) & 0x3u) != 0u) reject(programCounter, word0, std::string(entry->name) + " reserved bits are set");
        requireScalarRegister((word0 >> 8u) & 0x7fu, "VOP3 sdst", programCounter, word0);
        low = word0 & 0x7fffu;
    } else {
        const std::uint32_t absolute = (word0 >> 8u) & 0x7u;
        const std::uint32_t clamp = (word0 >> 11u) & 0x1u;
        if (((word0 >> 12u) & 0x1fu) != 0u) reject(programCounter, word0, std::string(entry->name) + " reserved bits are set");
        if (absolute != 0u && !entry->absolute) reject(programCounter, word0, std::string(entry->name) + " does not take the abs modifier");
        if (clamp != 0u && !entry->clamp) reject(programCounter, word0, std::string(entry->name) + " does not take the clamp modifier");
        if (opcode < 0x100u) requireScalarRegister(word0 & 0xffu, "VOP3 sdst", programCounter, word0);
        low = (clamp << 15u) | (absolute << 8u) | (word0 & 0xffu);
    }
    if (((word1 >> 27u) & 0x3u) != 0u && !entry->outputModifier) reject(programCounter, word0, std::string(entry->name) + " does not take an output modifier");
    if ((word1 >> 29u) != 0u && !entry->negate) reject(programCounter, word0, std::string(entry->name) + " does not take the neg modifier");
    requireVectorSource(word1 & 0x1ffu, false, "VOP3 src0", programCounter, word0);
    requireVectorSource((word1 >> 9u) & 0x1ffu, false, "VOP3 src1", programCounter, word0);
    requireVectorSource((word1 >> 18u) & 0x1ffu, false, "VOP3 src2", programCounter, word0);
    const std::array<std::uint32_t, 2> rewritten{(rdnaVop3Encoding << 26u) | (entry->rdnaOpcode << 16u) | low, word1};
    return decodeRewritten(programCounter, code, wordIndex, rewritten, 2u, false);
}

RdnaInstruction decodeSmrd(std::uint32_t programCounter, std::span<const std::uint32_t> code, std::uint32_t wordIndex) {
    const std::uint32_t word = code[wordIndex];
    const auto& entry = requireOpcode(GcnOpcodeFamily::Smrd, (word >> 22u) & 0x1fu, "SMRD", programCounter, word);
    const std::uint32_t offset = word & 0xffu;
    const bool immediate = ((word >> 8u) & 0x1u) != 0u;
    const std::uint32_t base = (word >> 9u) & 0x3fu;
    const std::uint32_t destination = (word >> 15u) & 0x7fu;
    std::uint32_t originalWords = 1u;
    std::uint32_t byteOffset = 0u;
    std::uint32_t scalarOffset = rdnaNullScalarRegister;
    if (entry.name == "s_memtime") {
        if (offset != 0u || immediate || base != 0u) reject(programCounter, word, "s_memtime operand fields are set");
        requireScalarRegister(destination, "SMRD sdst", programCounter, word);
    } else {
        const std::uint32_t dwords = 1u << entry.opcode;
        if (base * 2u + 2u > scalarRegisterCount) reject(programCounter, word, "SMRD base s" + std::to_string(base * 2u) + " is not supported");
        requireScalarRegister(destination, "SMRD sdst", programCounter, word);
        const bool registerPair = destination == 106u || destination == 126u;
        const bool fits = destination < scalarRegisterCount ? destination + dwords <= scalarRegisterCount : dwords == 1u || (dwords == 2u && registerPair);
        if (!fits) reject(programCounter, word, "SMRD destination range is not supported");
        if (immediate) {
            byteOffset = offset * 4u;
        } else if (offset == smrdLiteralOffset) {
            if (wordIndex + 1u >= code.size()) throw std::out_of_range("truncated gfx7 SMRD instruction");
            const std::uint32_t literal = code[wordIndex + 1u];
            if (literal >= 0x40000u) reject(programCounter, word, "SMRD literal offset " + toHexString(literal) + " exceeds the 21-bit byte offset");
            byteOffset = literal * 4u;
            originalWords = 2u;
        } else {
            if (offset >= scalarRegisterCount) reject(programCounter, word, "SMRD offset register code " + std::to_string(offset) + " is not supported");
            scalarOffset = offset;
        }
    }
    const std::array<std::uint32_t, 2> rewritten{
        (rdnaSmemEncoding << 26u) | (entry.rdnaOpcode << 18u) | (destination << 6u) | base,
        (scalarOffset << 25u) | byteOffset};
    auto instruction = DecodeRdnaInstruction(programCounter, rewritten, 0);
    instruction.wordCount = originalWords;
    SetRdnaRawWords(instruction, code, wordIndex, originalWords);
    return instruction;
}

RdnaInstruction decodeExport(std::uint32_t programCounter, std::span<const std::uint32_t> code, std::uint32_t wordIndex) {
    requireTwoWords(code, wordIndex, "EXP");
    const std::uint32_t word = code[wordIndex];
    const std::uint32_t target = (word >> 4u) & 0x3fu;
    if (((word >> 13u) & 0x1fffu) != 0u) reject(programCounter, word, "EXP reserved bits are set");
    if (!(target <= 9u || (target >= 12u && target <= 15u) || target >= 32u)) reject(programCounter, word, "EXP target " + std::to_string(target) + " is not supported");
    return decodeRewritten(programCounter, code, wordIndex, code.subspan(wordIndex, 2u), 2u, false);
}

RdnaInstruction decodeInterpolation(std::uint32_t programCounter, std::span<const std::uint32_t> code, std::uint32_t wordIndex) {
    const std::uint32_t word = code[wordIndex];
    requireOpcode(GcnOpcodeFamily::Vintrp, (word >> 16u) & 0x3u, "VINTRP", programCounter, word);
    return decodeRewritten(programCounter, code, wordIndex, code.subspan(wordIndex, 1u), 1u, false);
}

}

RdnaInstruction DecodeGcnInstruction(std::uint32_t programCounter, std::span<const std::uint32_t> code, std::uint32_t wordIndex) {
    if (wordIndex >= code.size()) throw std::out_of_range("word index is out of the code span bounds");
    const std::uint32_t word = code[wordIndex];
    const GcnEncoding encoding = classify(word);
    switch (encoding) {
        case GcnEncoding::Sop2:
        case GcnEncoding::Sopk:
        case GcnEncoding::Sop1:
        case GcnEncoding::Sopc:
        case GcnEncoding::Sopp:
            return decodeScalar(encoding, programCounter, code, wordIndex);
        case GcnEncoding::Vop1:
        case GcnEncoding::Vop2:
        case GcnEncoding::Vopc:
            return decodeVector(encoding, programCounter, code, wordIndex);
        case GcnEncoding::Vop3: return decodeVop3(programCounter, code, wordIndex);
        case GcnEncoding::Smrd: return decodeSmrd(programCounter, code, wordIndex);
        case GcnEncoding::Exp: return decodeExport(programCounter, code, wordIndex);
        case GcnEncoding::Vintrp: return decodeInterpolation(programCounter, code, wordIndex);
        case GcnEncoding::Ds: reject(programCounter, word, "DS instructions are not supported");
        case GcnEncoding::Flat: reject(programCounter, word, "FLAT instructions are not supported");
        case GcnEncoding::Mubuf: reject(programCounter, word, "MUBUF instructions are not supported");
        case GcnEncoding::Mtbuf: reject(programCounter, word, "MTBUF instructions are not supported");
        case GcnEncoding::Mimg: reject(programCounter, word, "MIMG instructions are not supported");
        case GcnEncoding::Unknown: break;
    }
    reject(programCounter, word, "instruction encoding is unknown");
}

void DecodeGcnProgram(std::span<const std::uint32_t> code, RdnaProgram& program) {
    program.instructions.clear();
    program.instructions.reserve(code.size());
    program.code = code;

    std::uint32_t furthestBranchTarget = 0;
    for (std::uint32_t wordIndex = 0; wordIndex < code.size();) {
        const std::uint32_t programCounter = wordIndex * static_cast<std::uint32_t>(sizeof(std::uint32_t));
        program.instructions.push_back(DecodeGcnInstruction(programCounter, code, wordIndex));

        const RdnaInstruction& instruction = program.instructions.back();
        wordIndex += instruction.wordCount;

        if (IsDirectBranchOpcode(instruction.op)) {
            const std::uint32_t targetIndex = instruction.branchTarget / static_cast<std::uint32_t>(sizeof(std::uint32_t));
            if (targetIndex >= code.size()) throw std::out_of_range("branch target is out of the code span bounds");
            furthestBranchTarget = std::max(furthestBranchTarget, targetIndex);
        }

        if (instruction.op == RdnaOpcode::SEndpgm && furthestBranchTarget < wordIndex) return;
    }

    throw std::out_of_range("gfx7 program decode reached the code boundary before s_endpgm");
}

}
