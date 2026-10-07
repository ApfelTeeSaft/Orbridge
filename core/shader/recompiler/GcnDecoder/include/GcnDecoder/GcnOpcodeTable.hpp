#ifndef CORE_SHADER_RECOMPILIER_GCNDECODER_INCLUDE_GCNDECODER_GCNOPCODETABLE_HPP
#define CORE_SHADER_RECOMPILIER_GCNDECODER_INCLUDE_GCNDECODER_GCNOPCODETABLE_HPP

#include <cstdint>
#include <string_view>

namespace ShaderRecompiler {

enum class GcnOpcodeFamily {
    Sop2,
    Sopk,
    Sop1,
    Sopc,
    Sopp,
    Vop1,
    Vop2,
    Vopc,
    Vintrp,
    Smrd
};

struct GcnOpcode {
    std::uint32_t opcode;
    std::uint32_t rdnaOpcode;
    std::string_view name;
};

struct GcnVop3Opcode {
    std::uint32_t opcode;
    std::uint32_t rdnaOpcode;
    std::string_view name;
    bool carryOut;
    bool clamp;
    bool outputModifier;
    bool negate;
    bool absolute;
};

[[nodiscard]] const GcnOpcode* FindGcnOpcode(GcnOpcodeFamily family, std::uint32_t opcode);
[[nodiscard]] const GcnVop3Opcode* FindGcnVop3Opcode(std::uint32_t opcode);

}

#endif
