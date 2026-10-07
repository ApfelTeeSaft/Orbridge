#include "GcnDecoder/GcnInstructionDecoder.hpp"
#include "RdnaDecoder/RdnaInstructionDecoder.hpp"
#include "RdnaDecoder/RdnaOpcode.hpp"
#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

using namespace ShaderRecompiler;

namespace {

struct Equivalent {
    const char* assembly;
    std::vector<std::uint32_t> gfx7;
    std::vector<std::uint32_t> gfx10;
};

struct Rejected {
    const char* assembly;
    std::vector<std::uint32_t> gfx7;
};

const std::vector<Equivalent> equivalents{
    {"s_mov_b32 s1, s2", {0xbe810302u}, {0xbe810302u}},
    {"s_mov_b32 s1, 0x12345678", {0xbe8103ffu, 0x12345678u}, {0xbe8103ffu, 0x12345678u}},
    {"s_mov_b32 s1, -4", {0xbe8103c4u}, {0xbe8103c4u}},
    {"s_mov_b32 s1, 0.5", {0xbe8103f0u}, {0xbe8103f0u}},
    {"s_mov_b32 s1, -4.0", {0xbe8103f7u}, {0xbe8103f7u}},
    {"s_mov_b64 s[2:3], exec", {0xbe82047eu}, {0xbe82047eu}},
    {"s_mov_b64 exec, s[2:3]", {0xbefe0402u}, {0xbefe0402u}},
    {"s_mov_b64 vcc, s[4:5]", {0xbeea0404u}, {0xbeea0404u}},
    {"s_mov_b32 m0, s3", {0xbefc0303u}, {0xbefc0303u}},
    {"s_mov_b32 s5, m0", {0xbe85037cu}, {0xbe85037cu}},
    {"s_mov_b32 s103, s0", {0xbee70300u}, {0xbee70300u}},
    {"s_not_b64 s[2:3], s[4:5]", {0xbe820804u}, {0xbe820804u}},
    {"s_brev_b32 s1, s2", {0xbe810b02u}, {0xbe810b02u}},
    {"s_bcnt1_i32_b64 s1, s[2:3]", {0xbe811002u}, {0xbe811002u}},
    {"s_ff1_i32_b32 s1, s2", {0xbe811302u}, {0xbe811302u}},
    {"s_flbit_i32 s1, s2", {0xbe811702u}, {0xbe811702u}},
    {"s_sext_i32_i16 s1, s2", {0xbe811a02u}, {0xbe811a02u}},
    {"s_bitset1_b32 s1, s2", {0xbe811d02u}, {0xbe811d02u}},
    {"s_getpc_b64 s[2:3]", {0xbe821f00u}, {0xbe821f00u}},
    {"s_setpc_b64 s[2:3]", {0xbe802002u}, {0xbe802002u}},
    {"s_and_saveexec_b64 s[2:3], vcc", {0xbe82246au}, {0xbe82246au}},
    {"s_andn2_saveexec_b64 s[2:3], s[4:5]", {0xbe822704u}, {0xbe822704u}},
    {"s_wqm_b64 exec, exec", {0xbefe0a7eu}, {0xbefe0a7eu}},
    {"s_movrels_b32 s1, s2", {0xbe812e02u}, {0xbe812e02u}},
    {"s_movreld_b64 s[2:3], s[4:5]", {0xbe823104u}, {0xbe823104u}},
    {"s_abs_i32 s1, s2", {0xbe813402u}, {0xbe813402u}},
    {"s_quadmask_b64 s[2:3], s[4:5]", {0xbe822d04u}, {0xbe822d04u}},
    {"s_cmov_b32 s1, s2", {0xbe810502u}, {0xbe810502u}},
    {"s_add_u32 s1, s2, s3", {0x80010302u}, {0x80010302u}},
    {"s_addc_u32 s1, s2, 7", {0x82018702u}, {0x82018702u}},
    {"s_sub_i32 s1, s2, 0xffff0000", {0x8181ff02u, 0xffff0000u}, {0x8181ff02u, 0xffff0000u}},
    {"s_and_b64 s[0:1], vcc, exec", {0x87807e6au}, {0x87807e6au}},
    {"s_andn2_b64 exec, exec, s[4:5]", {0x8afe047eu}, {0x8afe047eu}},
    {"s_lshl_b32 s1, s2, 3", {0x8f018302u}, {0x8f018302u}},
    {"s_lshl_b64 s[2:3], s[4:5], 3", {0x8f828304u}, {0x8f828304u}},
    {"s_bfe_u32 s1, s2, 0x80008", {0x9381ff02u, 0x00080008u}, {0x9381ff02u, 0x00080008u}},
    {"s_cselect_b32 s1, s2, s3", {0x85010302u}, {0x85010302u}},
    {"s_cselect_b64 s[2:3], s[4:5], 0", {0x85828004u}, {0x85828004u}},
    {"s_mul_i32 s1, s2, s3", {0x93010302u}, {0x93010302u}},
    {"s_bfm_b64 s[2:3], s4, s5", {0x92820504u}, {0x92820504u}},
    {"s_absdiff_i32 s1, s2, s3", {0x96010302u}, {0x96010302u}},
    {"s_ashr_i64 s[2:3], s[4:5], s6", {0x91820604u}, {0x91820604u}},
    {"s_min_u32 s1, s2, -1", {0x8381c102u}, {0x8381c102u}},
    {"s_xnor_b64 s[2:3], s[4:5], exec", {0x8e827e04u}, {0x8e827e04u}},
    {"s_cmp_eq_u32 s1, s2", {0xbf060201u}, {0xbf060201u}},
    {"s_cmp_lg_i32 s1, 0", {0xbf018001u}, {0xbf018001u}},
    {"s_cmp_lt_u32 s1, 0x10000", {0xbf0aff01u, 0x00010000u}, {0xbf0aff01u, 0x00010000u}},
    {"s_bitcmp1_b64 s[2:3], s4", {0xbf0f0402u}, {0xbf0f0402u}},
    {"s_cmp_ge_i32 vcc_lo, exec_hi", {0xbf037f6au}, {0xbf037f6au}},
    {"s_movk_i32 s1, 0x1234", {0xb0011234u}, {0xb0011234u}},
    {"s_cmovk_i32 s1, 0x7fff", {0xb1017fffu}, {0xb1017fffu}},
    {"s_cmpk_eq_i32 s1, 0x10", {0xb1810010u}, {0xb1810010u}},
    {"s_cmpk_lt_u32 s1, 0xffff", {0xb681ffffu}, {0xb681ffffu}},
    {"s_addk_i32 s1, 0x10", {0xb7810010u}, {0xb7810010u}},
    {"s_mulk_i32 s1, 0xfffe", {0xb801fffeu}, {0xb801fffeu}},
    {"s_nop 0", {0xbf800000u}, {0xbf800000u}},
    {"s_nop 7", {0xbf800007u}, {0xbf800007u}},
    {"s_endpgm", {0xbf810000u}, {0xbf810000u}},
    {"s_branch 3", {0xbf820003u}, {0xbf820003u}},
    {"s_branch 0xfffe", {0xbf82fffeu}, {0xbf82fffeu}},
    {"s_cbranch_scc0 2", {0xbf840002u}, {0xbf840002u}},
    {"s_cbranch_scc1 2", {0xbf850002u}, {0xbf850002u}},
    {"s_cbranch_vccz 2", {0xbf860002u}, {0xbf860002u}},
    {"s_cbranch_vccnz 2", {0xbf870002u}, {0xbf870002u}},
    {"s_cbranch_execz 2", {0xbf880002u}, {0xbf880002u}},
    {"s_cbranch_execnz 2", {0xbf890002u}, {0xbf890002u}},
    {"s_barrier", {0xbf8a0000u}, {0xbf8a0000u}},
    {"s_sleep 2", {0xbf8e0002u}, {0xbf8e0002u}},
    {"s_setprio 1", {0xbf8f0001u}, {0xbf8f0001u}},
    {"s_icache_inv", {0xbf930000u}, {0xbf930000u}},
    {"s_incperflevel 1", {0xbf940001u}, {0xbf940001u}},
    {"s_decperflevel 1", {0xbf950001u}, {0xbf950001u}},
    {"v_mov_b32 v1, v2", {0x7e020302u}, {0x7e020302u}},
    {"v_mov_b32 v1, s2", {0x7e020202u}, {0x7e020202u}},
    {"v_mov_b32 v1, 0x3f800000", {0x7e0202f2u}, {0x7e0202f2u}},
    {"v_mov_b32 v1, 1.0", {0x7e0202f2u}, {0x7e0202f2u}},
    {"v_mov_b32 v1, -16", {0x7e0202d0u}, {0x7e0202d0u}},
    {"v_mov_b32 v255, v0", {0x7ffe0300u}, {0x7ffe0300u}},
    {"v_mov_b32 v1, vcc_lo", {0x7e02026au}, {0x7e02026au}},
    {"v_mov_b32 v1, exec_hi", {0x7e02027fu}, {0x7e02027fu}},
    {"v_mov_b32 v1, m0", {0x7e02027cu}, {0x7e02027cu}},
    {"v_readfirstlane_b32 s1, v2", {0x7e020502u}, {0x7e020502u}},
    {"v_cvt_f32_i32 v1, v2", {0x7e020b02u}, {0x7e020b02u}},
    {"v_cvt_i32_f64 v1, v[2:3]", {0x7e020702u}, {0x7e020702u}},
    {"v_cvt_f64_f32 v[2:3], v4", {0x7e042104u}, {0x7e042104u}},
    {"v_rcp_f32 v1, v2", {0x7e025502u}, {0x7e025502u}},
    {"v_sqrt_f64 v[2:3], v[4:5]", {0x7e046904u}, {0x7e046904u}},
    {"v_sin_f32 v1, v2", {0x7e026b02u}, {0x7e026b02u}},
    {"v_frexp_mant_f32 v1, v2", {0x7e028102u}, {0x7e028102u}},
    {"v_cvt_f16_f32 v1, v2", {0x7e021502u}, {0x7e021502u}},
    {"v_cvt_f32_ubyte3 v1, v2", {0x7e022902u}, {0x7e022902u}},
    {"v_movrels_b32 v1, v2", {0x7e028702u}, {0x7e028702u}},
    {"v_not_b32 v1, s2", {0x7e026e02u}, {0x7e026e02u}},
    {"v_ffbh_u32 v1, v2", {0x7e027302u}, {0x7e027302u}},
    {"v_nop", {0x7e000000u}, {0x7e000000u}},
    {"v_clrexcp", {0x7e008200u}, {0x7e008200u}},
    {"v_floor_f32 v1, -0.5", {0x7e0248f1u}, {0x7e0248f1u}},
    {"v_add_f32 v1, v2, v3", {0x06020702u}, {0x06020702u}},
    {"v_add_f32 v1, s2, v3", {0x06020602u}, {0x06020602u}},
    {"v_add_f32 v1, 0x40490fdb, v3", {0x060206ffu, 0x40490fdbu}, {0x060206ffu, 0x40490fdbu}},
    {"v_sub_f32 v1, 1.0, v3", {0x080206f2u}, {0x080206f2u}},
    {"v_subrev_f32 v1, v2, v3", {0x0a020702u}, {0x0a020702u}},
    {"v_mul_f32 v1, v2, v3", {0x10020702u}, {0x10020702u}},
    {"v_mul_legacy_f32 v1, v2, v3", {0x0e020702u}, {0x0e020702u}},
    {"v_mac_f32 v1, v2, v3", {0x3e020702u}, {0x3e020702u}},
    {"v_mac_legacy_f32 v1, v2, v3", {0x0c020702u}, {0x0c020702u}},
    {"v_madmk_f32 v1, v2, 0x41200000, v3", {0x40020702u, 0x41200000u}, {0x40020702u, 0x41200000u}},
    {"v_madak_f32 v1, v2, v3, 0x41200000", {0x42020702u, 0x41200000u}, {0x42020702u, 0x41200000u}},
    {"v_min_f32 v1, v2, v3", {0x1e020702u}, {0x1e020702u}},
    {"v_max_i32 v1, v2, v3", {0x24020702u}, {0x24020702u}},
    {"v_min_u32 v1, s2, v3", {0x26020602u}, {0x26020602u}},
    {"v_lshlrev_b32 v1, 4, v3", {0x34020684u}, {0x34020684u}},
    {"v_ashrrev_i32 v1, v2, v3", {0x30020702u}, {0x30020702u}},
    {"v_and_b32 v1, 0xff, v3", {0x360206ffu, 0x000000ffu}, {0x360206ffu, 0x000000ffu}},
    {"v_xor_b32 v1, v2, v3", {0x3a020702u}, {0x3a020702u}},
    {"v_mul_u32_u24 v1, v2, v3", {0x16020702u}, {0x16020702u}},
    {"v_mul_hi_i32_i24 v1, v2, v3", {0x14020702u}, {0x14020702u}},
    {"v_cvt_pkrtz_f16_f32 v1, v2, v3", {0x5e020702u}, {0x5e020702u}},
    {"v_cndmask_b32 v1, v2, v3, vcc", {0x00020702u}, {0x02020702u}},
    {"v_cndmask_b32 v1, 0, v3, vcc", {0x00020680u}, {0x02020680u}},
    {"v_cmp_lt_f32 vcc, v1, v2", {0x7c020501u}, {0x7c020501u}},
    {"v_cmp_eq_u32 vcc, s1, v2", {0x7d840401u}, {0x7d840401u}},
    {"v_cmp_ne_i32 vcc, 0, v2", {0x7d0a0480u}, {0x7d0a0480u}},
    {"v_cmp_gt_f64 vcc, v[2:3], v[4:5]", {0x7c480902u}, {0x7c480902u}},
    {"v_cmp_class_f32 vcc, v1, v2", {0x7d100501u}, {0x7d100501u}},
    {"v_cmp_u_f32 vcc, v1, v2", {0x7c100501u}, {0x7c100501u}},
    {"v_cmp_ge_u64 vcc, v[2:3], v[4:5]", {0x7dcc0902u}, {0x7dcc0902u}},
    {"v_cmp_t_i32 vcc, v1, v2", {0x7d0e0501u}, {0x7d0e0501u}},
    {"v_cmp_neq_f32 vcc, 1.0, v2", {0x7c1a04f2u}, {0x7c1a04f2u}},
    {"v_cmp_lt_i32 vcc, 0x12345, v2", {0x7d0204ffu, 0x00012345u}, {0x7d0204ffu, 0x00012345u}},
    {"v_cmp_class_f64 vcc, v[2:3], v4", {0x7d500902u}, {0x7d500902u}},
    {"v_add_f32_e64 v1, v2, v3", {0xd2060001u, 0x00020702u}, {0xd5030001u, 0x00020702u}},
    {"v_add_f32_e64 v1, v2, v3 clamp", {0xd2060801u, 0x00020702u}, {0xd5038001u, 0x00020702u}},
    {"v_add_f32_e64 v1, |v2|, -v3", {0xd2060101u, 0x40020702u}, {0xd5030101u, 0x40020702u}},
    {"v_mul_f32_e64 v1, v2, v3 mul:2", {0xd2100001u, 0x08020702u}, {0xd5080001u, 0x08020702u}},
    {"v_mul_f32_e64 v1, v2, v3 div:2", {0xd2100001u, 0x18020702u}, {0xd5080001u, 0x18020702u}},
    {"v_mad_f32 v1, v2, v3, v4", {0xd2820001u, 0x04120702u}, {0xd5410001u, 0x04120702u}},
    {"v_mad_f32 v1, -v2, |v3|, s4 clamp", {0xd2820a01u, 0x20120702u}, {0xd5418201u, 0x20120702u}},
    {"v_mad_legacy_f32 v1, v2, v3, v4", {0xd2800001u, 0x04120702u}, {0xd5400001u, 0x04120702u}},
    {"v_fma_f32 v1, v2, v3, v4", {0xd2960001u, 0x04120702u}, {0xd54b0001u, 0x04120702u}},
    {"v_fma_f64 v[2:3], v[4:5], v[6:7], v[8:9]", {0xd2980002u, 0x04220d04u}, {0xd54c0002u, 0x04220d04u}},
    {"v_bfe_u32 v1, v2, 8, 8", {0xd2900001u, 0x02211102u}, {0xd5480001u, 0x02211102u}},
    {"v_bfi_b32 v1, v2, v3, v4", {0xd2940001u, 0x04120702u}, {0xd54a0001u, 0x04120702u}},
    {"v_alignbit_b32 v1, v2, v3, 16", {0xd29c0001u, 0x02420702u}, {0xd54e0001u, 0x02420702u}},
    {"v_med3_f32 v1, v2, v3, v4", {0xd2ae0001u, 0x04120702u}, {0xd5570001u, 0x04120702u}},
    {"v_min3_i32 v1, v2, v3, v4", {0xd2a40001u, 0x04120702u}, {0xd5520001u, 0x04120702u}},
    {"v_max3_u32 v1, v2, s3, v4", {0xd2ac0001u, 0x04100702u}, {0xd5560001u, 0x04100702u}},
    {"v_mad_u32_u24 v1, v2, v3, v4", {0xd2860001u, 0x04120702u}, {0xd5430001u, 0x04120702u}},
    {"v_mul_lo_u32 v1, v2, v3", {0xd2d20001u, 0x00020702u}, {0xd5690001u, 0x00020702u}},
    {"v_mul_hi_u32 v1, v2, s3", {0xd2d40001u, 0x00000702u}, {0xd56a0001u, 0x00000702u}},
    {"v_mul_lo_i32 v1, v2, v3", {0xd2d60001u, 0x00020702u}, {0xd56b0001u, 0x00020702u}},
    {"v_mad_u64_u32 v[2:3], s[4:5], v1, v2, v[6:7]", {0xd2ec0402u, 0x041a0501u}, {0xd5760402u, 0x041a0501u}},
    {"v_mad_i64_i32 v[2:3], vcc, v1, v2, v[6:7]", {0xd2ee6a02u, 0x041a0501u}, {0xd5776a02u, 0x041a0501u}},
    {"v_div_scale_f64 v[2:3], vcc, v[4:5], v[6:7], v[8:9]", {0xd2dc6a02u, 0x04220d04u}, {0xd56e6a02u, 0x04220d04u}},
    {"v_div_scale_f64 v[2:3], s[4:5], -v[4:5], v[6:7], v[8:9]", {0xd2dc0402u, 0x24220d04u}, {0xd56e0402u, 0x24220d04u}},
    {"v_div_fmas_f32 v1, v2, v3, v4", {0xd2de0001u, 0x04120702u}, {0xd56f0001u, 0x04120702u}},
    {"v_div_fixup_f32 v1, v2, v3, v4", {0xd2be0001u, 0x04120702u}, {0xd55f0001u, 0x04120702u}},
    {"v_cubeid_f32 v1, v2, v3, v4", {0xd2880001u, 0x04120702u}, {0xd5440001u, 0x04120702u}},
    {"v_cubema_f32 v1, v2, v3, v4", {0xd28e0001u, 0x04120702u}, {0xd5470001u, 0x04120702u}},
    {"v_sad_u32 v1, v2, v3, v4", {0xd2ba0001u, 0x04120702u}, {0xd55d0001u, 0x04120702u}},
    {"v_lerp_u8 v1, v2, v3, v4", {0xd29a0001u, 0x04120702u}, {0xd54d0001u, 0x04120702u}},
    {"v_cvt_pk_u8_f32 v1, v2, 1, v4", {0xd2bc0001u, 0x04110302u}, {0xd55e0001u, 0x04110302u}},
    {"v_add_f64 v[2:3], v[4:5], v[6:7]", {0xd2c80002u, 0x00020d04u}, {0xd5640002u, 0x00020d04u}},
    {"v_ldexp_f64 v[2:3], v[4:5], v6", {0xd2d00002u, 0x00020d04u}, {0xd5680002u, 0x00020d04u}},
    {"v_trig_preop_f64 v[2:3], v[4:5], v6", {0xd2e80002u, 0x00020d04u}, {0xd5740002u, 0x00020d04u}},
    {"v_cmp_lt_f32_e64 s[2:3], v1, v2", {0xd0020002u, 0x00020501u}, {0xd4010002u, 0x00020501u}},
    {"v_cmp_lt_f32_e64 s[2:3], -v1, |v2|", {0xd0020202u, 0x20020501u}, {0xd4010202u, 0x20020501u}},
    {"v_cmp_eq_u32_e64 vcc, s1, v2", {0xd184006au, 0x00020401u}, {0xd4c2006au, 0x00020401u}},
    {"v_cmp_ge_f64_e64 s[2:3], v[2:3], v[4:5]", {0xd04c0002u, 0x00020902u}, {0xd4260002u, 0x00020902u}},
    {"v_mov_b32_e64 v1, s2", {0xd3020001u, 0x00000002u}, {0xd5810001u, 0x00000002u}},
    {"v_rcp_f32_e64 v1, -v2 clamp", {0xd3540801u, 0x20000102u}, {0xd5aa8001u, 0x20000102u}},
    {"v_cvt_f32_i32_e64 v1, s2 mul:2", {0xd30a0001u, 0x08000002u}, {0xd5850001u, 0x08000002u}},
    {"v_cndmask_b32_e64 v1, v2, v3, s[4:5]", {0xd2000001u, 0x00120702u}, {0xd5010001u, 0x00120702u}},
    {"v_bfm_b32_e64 v1, v2, v3", {0xd23c0001u, 0x00020702u}, {0xd7630001u, 0x00020702u}},
    {"v_bcnt_u32_b32_e64 v1, v2, v3", {0xd2440001u, 0x00020702u}, {0xd7640001u, 0x00020702u}},
    {"v_mbcnt_lo_u32_b32_e64 v1, -1, 0", {0xd2460001u, 0x000100c1u}, {0xd7650001u, 0x000100c1u}},
    {"v_mbcnt_hi_u32_b32_e64 v1, -1, v1", {0xd2480001u, 0x000202c1u}, {0xd7660001u, 0x000202c1u}},
    {"v_ldexp_f32_e64 v1, v2, v3", {0xd2560001u, 0x00020702u}, {0xd7620001u, 0x00020702u}},
    {"v_cvt_pknorm_i16_f32_e64 v1, v2, v3", {0xd25a0001u, 0x00020702u}, {0xd7680001u, 0x00020702u}},
    {"v_cvt_pknorm_u16_f32_e64 v1, v2, v3", {0xd25c0001u, 0x00020702u}, {0xd7690001u, 0x00020702u}},
    {"v_cvt_pk_u16_u32_e64 v1, v2, v3", {0xd2600001u, 0x00020702u}, {0xd76a0001u, 0x00020702u}},
    {"v_cvt_pk_i16_i32_e64 v1, v2, v3", {0xd2620001u, 0x00020702u}, {0xd76b0001u, 0x00020702u}},
    {"v_mac_f32_e64 v1, v2, v3", {0xd23e0001u, 0x00020702u}, {0xd51f0001u, 0x00020702u}},
    {"v_mul_legacy_f32_e64 v1, v2, v3", {0xd20e0001u, 0x00020702u}, {0xd5070001u, 0x00020702u}},
    {"v_sin_f32_e64 v1, v2 div:2", {0xd36a0001u, 0x18000102u}, {0xd5b50001u, 0x18000102u}},
    {"v_cvt_i32_f32_e64 v1, -v2", {0xd3100001u, 0x20000102u}, {0xd5880001u, 0x20000102u}},
    {"v_interp_p1_f32 v1, v2, attr0.x", {0xc8040002u}, {0xc8040002u}},
    {"v_interp_p2_f32 v1, v2, attr3.w", {0xc8050f02u}, {0xc8050f02u}},
    {"v_interp_mov_f32 v1, p10, attr31.y", {0xc8067d00u}, {0xc8067d00u}},
    {"v_interp_mov_f32 v1, p0, attr1.z", {0xc8060602u}, {0xc8060602u}},
    {"exp pos0 v0, v1, v2, v3 done", {0xf80008cfu, 0x03020100u}, {0xf80008cfu, 0x03020100u}},
    {"exp mrt0 v0, v0, v1, v1 compr vm", {0xf800140fu, 0x00000100u}, {0xf800140fu, 0x00000100u}},
    {"exp param31 v4, v5, v6, v7", {0xf80003ffu, 0x07060504u}, {0xf80003ffu, 0x07060504u}},
    {"exp mrtz v0, off, off, off done vm", {0xf8001881u, 0x00000000u}, {0xf8001881u, 0x00000000u}},
    {"exp null off, off, off, off done", {0xf8000890u, 0x00000000u}, {0xf8000890u, 0x00000000u}},
    {"exp mrt7 v1, v2, off, off", {0xf8000073u, 0x00000201u}, {0xf8000073u, 0x00000201u}},
    {"s_load_dword s1, s[2:3], 0x4", {0xc0008304u}, {0xf4000041u, 0xfa000010u}},
    {"s_load_dwordx2 s[4:5], s[2:3], 0xff", {0xc04203ffu}, {0xf4040101u, 0xfa0003fcu}},
    {"s_load_dwordx4 s[4:7], s[2:3], 0x0", {0xc0820300u}, {0xf4080101u, 0xfa000000u}},
    {"s_load_dwordx8 s[8:15], s[2:3], 0x10", {0xc0c40310u}, {0xf40c0201u, 0xfa000040u}},
    {"s_load_dwordx16 s[16:31], s[100:101], 0x2", {0xc1086502u}, {0xf4100432u, 0xfa000008u}},
    {"s_load_dword s1, s[2:3], s4", {0xc0008204u}, {0xf4000041u, 0x08000000u}},
    {"s_load_dword s1, s[2:3], 0x400", {0xc00082ffu, 0x00000400u}, {0xf4000041u, 0xfa001000u}},
    {"s_load_dwordx2 vcc, s[2:3], 0x1", {0xc0750301u}, {0xf4041a81u, 0xfa000004u}},
    {"s_memtime s[2:3]", {0xc7810000u}, {0xf4900080u, 0x00000000u}},
    {"s_waitcnt 0", {0xbf8c0000u}, {0xbf8c0000u}},
    {"s_waitcnt vmcnt(0)", {0xbf8c0f70u}, {0xbf8c3f70u}},
    {"s_waitcnt lgkmcnt(0)", {0xbf8c007fu}, {0xbf8cc07fu}},
    {"s_waitcnt vmcnt(1) expcnt(2) lgkmcnt(3)", {0xbf8c0321u}, {0xbf8c0321u}},
    {"s_waitcnt expcnt(0)", {0xbf8c0f0fu}, {0xbf8cff0fu}},
    {"s_waitcnt vmcnt(15)", {0xbf8c0f7fu}, {0xbf8cff7fu}},
};

const std::vector<Rejected> rejected{
    {"v_cmpx_lt_f32 vcc, v1, v2", {0x7c220501u}},
    {"v_cmpx_lt_f32_e64 s[2:3], v1, v2", {0xd0220002u, 0x00020501u}},
    {"s_mov_b32 s1, flat_scratch_lo", {0xbe810368u}},
    {"s_mov_b32 flat_scratch_hi, s1", {0xbee90301u}},
    {"s_mov_b32 s1, tba_lo", {0xbe81036cu}},
    {"s_mov_b32 s1, ttmp0", {0xbe810370u}},
    {"v_mov_b32 v1, flat_scratch_lo", {0x7e020268u}},
    {"s_getreg_b32 s1, hwreg(HW_REG_MODE)", {0xb901f801u}},
    {"s_setreg_b32 hwreg(HW_REG_MODE), s1", {0xb981f801u}},
    {"s_sendmsg sendmsg(MSG_GS, GS_OP_EMIT, 0)", {0xbf900022u}},
    {"s_trap 2", {0xbf920002u}},
    {"s_setkill 1", {0xbf8b0001u}},
    {"s_rfe_b64 s[2:3]", {0xbe802202u}},
    {"s_sethalt 1", {0xbf8d0001u}},
    {"s_buffer_load_dword s1, s[4:7], 0x4", {0xc2008504u}},
    {"buffer_load_dword v1, off, s[4:7], 0", {0xe0300000u, 0x80010100u}},
    {"tbuffer_load_format_x v1, off, s[4:7], dfmt:4, nfmt:4, 0", {0xea200000u, 0x80010100u}},
    {"image_sample v[0:3], v[4:5], s[8:15], s[16:19] dmask:0xf", {0xf0800f00u, 0x00820004u}},
    {"ds_read_b32 v1, v2", {0xd8d80000u, 0x01000002u}},
    {"flat_load_dword v1, v[2:3]", {0xdc300000u, 0x01000002u}},
    {"v_add_i32 v1, vcc, v2, v3", {0x4a020702u}},
    {"v_lshl_b32 v1, v2, v3", {0x32020702u}},
    {"v_min_legacy_f32 v1, v2, v3", {0x1a020702u}},
    {"v_rcp_legacy_f32 v1, v2", {0x7e025302u}},
    {"s_dcache_inv", {0xc7c00000u}},
    {"v_readlane_b32 s1, v2, s3", {0x02020702u}},
    {"v_div_scale_f32 v1, vcc, v2, v3, v4", {0xd2da6a01u, 0x04120702u}},
    {"s_bfe_i32 s1, s2, flat_scratch_hi", {0x94016902u}},
    {"v_cmp_lt_f32 vcc, ttmp1, v2", {0x7c020471u}},
};

bool sameOperand(const RdnaOperand& left, const RdnaOperand& right) {
    return left.kind == right.kind && left.value == right.value && left.signedVal == right.signedVal && left.reg == right.reg &&
        left.sdwaSel == right.sdwaSel && left.sdwaDstUnused == right.sdwaDstUnused && left.omod == right.omod && left.dppCtrl == right.dppCtrl &&
        left.dppRowMask == right.dppRowMask && left.dppBankMask == right.dppBankMask && left.explicitSdwaDst == right.explicitSdwaDst &&
        left.sdwaSext == right.sdwaSext && left.dppFetchInactive == right.dppFetchInactive && left.dppBoundCtrl == right.dppBoundCtrl &&
        left.opSel == right.opSel && left.opSelHi == right.opSelHi && left.negate == right.negate && left.negateHi == right.negateHi &&
        left.absolute == right.absolute && left.clamp == right.clamp && left.dpp == right.dpp && left.dpp8 == right.dpp8;
}

std::string difference(const RdnaInstruction& gcn, const RdnaInstruction& rdna, bool sameLength) {
    if (gcn.op != rdna.op) return "op";
    if (gcn.family != rdna.family) return "family";
    if (gcn.opcodeId != rdna.opcodeId) return "opcode";
    if (sameLength && gcn.wordCount != rdna.wordCount) return "word count";
    if (!sameOperand(gcn.destination, rdna.destination)) return "destination";
    if (!sameOperand(gcn.destination2, rdna.destination2)) return "destination2";
    if (!sameOperand(gcn.source0, rdna.source0)) return "source0";
    if (!sameOperand(gcn.source1, rdna.source1)) return "source1";
    if (!sameOperand(gcn.source2, rdna.source2)) return "source2";
    if (!sameOperand(gcn.source3, rdna.source3)) return "source3";
    if (gcn.sourceCount != rdna.sourceCount) return "source count";
    if (gcn.branchOffset != rdna.branchOffset || gcn.branchTarget != rdna.branchTarget) return "branch";
    if (gcn.memoryOffset != rdna.memoryOffset || gcn.secondaryOffset != rdna.secondaryOffset) return "memory offset";
    if (gcn.dataDwordCount != rdna.dataDwordCount || gcn.dataComponents != rdna.dataComponents || gcn.dataBits != rdna.dataBits) return "data size";
    if (gcn.dataFormat != rdna.dataFormat || gcn.numberFormat != rdna.numberFormat || gcn.dataSigned != rdna.dataSigned) return "data format";
    if (gcn.typed != rdna.typed || gcn.formatted != rdna.formatted || gcn.memorySegment != rdna.memorySegment) return "memory kind";
    if (gcn.clampResult != rdna.clampResult || gcn.is64Bit != rdna.is64Bit) return "result flags";
    if (gcn.exportTarget != rdna.exportTarget || gcn.exportEnableMask != rdna.exportEnableMask || gcn.exportIsCompressed != rdna.exportIsCompressed ||
        gcn.exportIsLast != rdna.exportIsLast || gcn.exportValidMask != rdna.exportValidMask) return "export";
    if (gcn.glc != rdna.glc || gcn.dlc != rdna.dlc || gcn.slc != rdna.slc || gcn.gds != rdna.gds || gcn.idxen != rdna.idxen || gcn.offen != rdna.offen) return "memory flags";
    if (gcn.unsupportedReason != rdna.unsupportedReason) return "unsupported reason";
    return {};
}

int checkEquivalents() {
    int failures = 0;
    for (const auto& entry : equivalents) {
        try {
            const auto gcn = DecodeGcnInstruction(0x40u, entry.gfx7, 0u);
            const auto rdna = DecodeRdnaInstruction(0x40u, entry.gfx10, 0u);
            const bool sameLength = entry.gfx7.size() == entry.gfx10.size();
            const auto mismatch = difference(gcn, rdna, sameLength);
            if (!mismatch.empty()) {
                std::fprintf(stderr, "%s: %s differs\n  gfx7  %s\n  gfx10 %s\n", entry.assembly, mismatch.c_str(), RdnaInstructionToString(gcn).c_str(), RdnaInstructionToString(rdna).c_str());
                ++failures;
            }
            if (gcn.wordCount != entry.gfx7.size()) {
                std::fprintf(stderr, "%s: word count %u, expected %zu\n", entry.assembly, gcn.wordCount, entry.gfx7.size());
                ++failures;
            }
            for (std::size_t index = 0; index < entry.gfx7.size(); ++index) {
                if (gcn.rawWords[index] != entry.gfx7[index]) {
                    std::fprintf(stderr, "%s: raw word %zu is not the gfx7 word\n", entry.assembly, index);
                    ++failures;
                }
            }
        } catch (const std::exception& error) {
            std::fprintf(stderr, "%s: %s\n", entry.assembly, error.what());
            ++failures;
        }
    }
    return failures;
}

int checkRejected() {
    int failures = 0;
    for (const auto& entry : rejected) {
        try {
            static_cast<void>(DecodeGcnInstruction(0u, entry.gfx7, 0u));
            std::fprintf(stderr, "%s: decoded although its gfx7 meaning is not supported\n", entry.assembly);
            ++failures;
        } catch (const std::invalid_argument&) {
        }
    }
    return failures;
}

int expectInvalid(const char* name, std::initializer_list<std::uint32_t> words, const char* message) {
    const std::vector<std::uint32_t> code(words);
    try {
        static_cast<void>(DecodeGcnInstruction(0u, code, 0u));
    } catch (const std::invalid_argument& error) {
        if (std::string(error.what()).find(message) != std::string::npos) return 0;
        std::fprintf(stderr, "%s: %s\n", name, error.what());
        return 1;
    }
    std::fprintf(stderr, "%s: decoded\n", name);
    return 1;
}

int checkCraftedEncodings() {
    int failures = 0;
    failures += expectInvalid("VOP3 literal", {0xd2060001u, 0x0001ff02u, 0x3f800000u}, "VOP3 src1 operand code 255");
    failures += expectInvalid("integer clamp", {0xd2d20801u, 0x00020702u}, "v_mul_lo_u32 does not take the clamp modifier");
    failures += expectInvalid("integer neg", {0xd2360001u, 0x20020702u}, "v_and_b32 does not take the neg modifier");
    failures += expectInvalid("integer omod", {0xd2360001u, 0x08020702u}, "v_and_b32 does not take an output modifier");
    failures += expectInvalid("VOP3 reserved", {0xd2061001u, 0x00020702u}, "v_add_f32 reserved bits are set");
    failures += expectInvalid("VOP3b reserved", {0xd2ec8402u, 0x042a1106u}, "v_mad_u64_u32 reserved bits are set");
    failures += expectInvalid("SMRD literal", {0xc00082ffu, 0x40000u}, "exceeds the 21-bit byte offset");
    failures += expectInvalid("SMRD base", {0xc000e904u}, "SMRD base s104");
    failures += expectInvalid("SMRD range", {0xc0b30104u}, "SMRD destination range");
    failures += expectInvalid("SMRD offset register", {0xc0008068u}, "SMRD offset register code 104");
    failures += expectInvalid("EXP target", {0xf80000afu, 0x03020100u}, "EXP target 10");
    failures += expectInvalid("EXP pos4", {0xf800010fu, 0x03020100u}, "EXP target 16");
    failures += expectInvalid("waitcnt reserved", {0xbf8c107fu}, "s_waitcnt reserved bits");
    failures += expectInvalid("unknown encoding", {0xfc000000u}, "instruction encoding is unknown");
    return failures;
}

int checkTruncated() {
    int failures = 0;
    const std::vector<std::uint32_t> literal{0xbe8103ffu};
    const std::vector<std::uint32_t> vop3{0xd2060001u};
    const std::vector<std::uint32_t> smrd{0xc00082ffu};
    for (const auto* code : {&literal, &vop3, &smrd}) {
        try {
            static_cast<void>(DecodeGcnInstruction(0u, *code, 0u));
            std::fprintf(stderr, "truncated instruction 0x%08x decoded\n", code->front());
            ++failures;
        } catch (const std::out_of_range&) {
        }
    }
    return failures;
}

int checkProgram() {
    const std::vector<std::uint32_t> code{
        0xbf840002u,
        0x7e020202u,
        0xbf810000u,
        0x7e020203u,
        0xbf810000u,
    };
    RdnaProgram program;
    DecodeGcnProgram(code, program);
    int failures = 0;
    if (program.instructions.size() != 5u || program.instructions[0].branchTarget != 0x0cu || program.instructions[4].op != RdnaOpcode::SEndpgm) {
        std::fprintf(stderr, "program decode did not follow the branch past the first s_endpgm\n");
        ++failures;
    }
    try {
        RdnaProgram unterminated;
        DecodeGcnProgram(std::span(code).first(2), unterminated);
        std::fprintf(stderr, "a program without s_endpgm decoded\n");
        ++failures;
    } catch (const std::out_of_range&) {
    }
    return failures;
}

}

int main() {
    const int failures = checkEquivalents() + checkRejected() + checkCraftedEncodings() + checkTruncated() + checkProgram();
    if (failures != 0) {
        std::fprintf(stderr, "%d GCN decode checks failed\n", failures);
        return 1;
    }
    std::printf("GCN decode tests passed (%zu equivalent encodings, %zu rejected)\n", equivalents.size(), rejected.size());
    return 0;
}
