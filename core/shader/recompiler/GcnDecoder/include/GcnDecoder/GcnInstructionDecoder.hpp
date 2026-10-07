#ifndef CORE_SHADER_RECOMPILIER_GCNDECODER_INCLUDE_GCNDECODER_GCNINSTRUCTIONDECODER_HPP
#define CORE_SHADER_RECOMPILIER_GCNDECODER_INCLUDE_GCNDECODER_GCNINSTRUCTIONDECODER_HPP

#include "RdnaDecoder/RdnaProgram.hpp"
#include <cstdint>
#include <span>

namespace ShaderRecompiler {

[[nodiscard]] RdnaInstruction DecodeGcnInstruction(std::uint32_t programCounter, std::span<const std::uint32_t> code, std::uint32_t wordIndex);
void DecodeGcnProgram(std::span<const std::uint32_t> code, RdnaProgram& program);

}

#endif
