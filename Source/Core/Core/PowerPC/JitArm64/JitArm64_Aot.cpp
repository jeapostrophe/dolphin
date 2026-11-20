// Copyright 2026 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

// JitArm64's AOT form: the modes are JitArm64_Aot.h's. This file is the image format's one home.
//
// An image is <prefix>.code and <prefix>.meta, linked into one dylib by retro-trainer's
// `cores/cores.sh aot link` (the code in __TEXT,__text between rt_aot_code and rt_aot_code_end,
// the meta in __TEXT,__const between rt_aot_meta and rt_aot_meta_end). The code is the shared
// routines (GenerateAsm's, AOT-shaped), from offset 0, then the blocks. The meta, little-endian, is
// ImageHeader, then u32 words: the routines' size, R_COUNT, the routine entry offsets
// (JitArm64::AotRoutines's order, then the quantized tables'), the link count and each link's
// ea and feature_flags (its slot is its index; "Links", below), then per block
//   ea, feature_flags, nops, nhooks, nfacts, code_off, code_len, ops[2 * nops] (each op's address
//   and word), hooks[2 * nhooks] (each op address HLE hooks, and its hook index), facts[4 * nfacts]
//   ("Facts", below),
// the ops in the order the analyzer left them. A block's key is its address, feature flags, ops and
// hooks: the hooks are the game's symbol state where it was compiled (HLE::GetHookByFunctionAddress),
// which changes as the game runs, and they change the code. A load refuses an image unless each checked header
// field is this core's (CheckHeader names the first that differs, with both values); a block is
// installed only where the analyzer, run on live memory, gives exactly its ops, and its facts hold.

#include "Core/PowerPC/JitArm64/JitArm64_Aot.h"

#include <algorithm>
#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <mutex>
#include <set>

#ifndef _WIN32
#include <dlfcn.h>
#include <unistd.h>
#endif

#ifdef __APPLE__
#include <TargetConditionals.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#if TARGET_OS_OSX
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif
#endif

#include "Common/CPUDetect.h"
#include "Common/FloatUtils.h"
#include "Core/ConfigManager.h"
#include "Core/CoreTiming.h"
#include "Core/HLE/HLE.h"
#include "Core/HW/CPU.h"
#include "Core/HW/GPFifo.h"
#include "Core/HW/Memmap.h"
#include "Core/HW/ProcessorInterface.h"
#include "Core/PowerPC/CachedInterpreter/CachedInterpreter.h"
#include "Core/PowerPC/ConditionRegister.h"
#include "Core/PowerPC/Interpreter/Interpreter.h"
#include "Core/PowerPC/JitArm64/Jit.h"
#include "Core/PowerPC/PPCSymbolDB.h"
#include "Core/PowerPC/JitCommon/JitAsmCommon.h"
#include "Core/PowerPC/JitInterface.h"
#include "Core/PowerPC/MMU.h"
#include "Core/PowerPC/PowerPC.h"
#include "Core/System.h"

using namespace Arm64Gen;

namespace JitArm64Aot
{
static Settings s_settings;
static std::mutex s_report_mutex;
static bool s_report_pending = false;
static bool s_report_admitted = false;
static std::string s_report_detail;

bool ParseMode(const char* text, Mode* mode)
{
  static const std::pair<const char*, Mode> modes[] = {
      {"shape", Mode::Shape}, {"emit", Mode::Emit}, {"load", Mode::Load}, {"interp", Mode::Interp}};
  for (const auto& [name, m] : modes)
  {
    if (!strcmp(text, name))
    {
      *mode = m;
      return true;
    }
  }
  return false;
}

void Configure(const Settings& settings)
{
  s_settings = settings;
}

const Settings& GetSettings()
{
  return s_settings;
}

void Report(bool admitted, std::string detail)
{
  std::lock_guard lock(s_report_mutex);
  s_report_pending = true;
  s_report_admitted = admitted;
  s_report_detail = std::move(detail);
}

bool TakeReport(bool* admitted, std::string* detail)
{
  std::lock_guard lock(s_report_mutex);
  if (!s_report_pending)
    return false;
  s_report_pending = false;
  *admitted = s_report_admitted;
  *detail = s_report_detail;
  return true;
}

u64 Fnv64(const void* data, size_t size, u64 h)
{
  const u8* p = static_cast<const u8*>(data);
  for (size_t i = 0; i < size; i++)
    h = (h ^ p[i]) * 0x100000001b3ULL;
  return h;
}

static u64 FnvString(const std::string& s, u64 h)
{
  return Fnv64(s.c_str(), s.size() + 1, h);
}

int Imports::Slot(const void* target) const
{
  const auto it = slot_of.find(target);
  return it == slot_of.end() ? -1 : it->second;
}

void Imports::Unresolved(const void* target, const char* what)
{
  unresolved_in_unit++;
  auto [it, fresh] = unresolved_seen.emplace(target, what);
  if (fresh)
  {
#ifndef _WIN32
    Dl_info info{};
    const char* sym = dladdr(target, &info) && info.dli_sname ? info.dli_sname : "?";
    const uintptr_t base = reinterpret_cast<uintptr_t>(info.dli_fbase);
    fprintf(stderr, "JitArm64 AOT: unresolved %s %p (%s, image offset %#" PRIxPTR ")\n", what,
            target, sym, base ? reinterpret_cast<uintptr_t>(target) - base : 0);
#else
    fprintf(stderr, "JitArm64 AOT: unresolved %s %p\n", what, target);
#endif
  }
}

int Imports::Add(const std::string& name, const void* value)
{
  const int slot = static_cast<int>(names.size());
  ASSERT_MSG(DYNA_REC, slot < static_cast<int>(PowerPC::PowerPCState::AOT_IMPORT_SLOTS),
             "AOT import table full");
  names.push_back(name);
  values.push_back(value);
  if (value)
    slot_of.emplace(value, slot);
  return slot;
}

void Imports::Set(int slot, const void* value)
{
  values[slot] = value;
  slot_of.emplace(value, slot);
}

void VMReport(const char* label)
{
#if defined(__APPLE__) && TARGET_OS_OSX
  mach_vm_address_t addr = 0;
  u32 exec = 0, wx = 0, anon_exec = 0;
  while (true)
  {
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    if (mach_vm_region(mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64,
                       reinterpret_cast<vm_region_info_t>(&info), &count, &object) != KERN_SUCCESS)
      break;
    if (info.protection & VM_PROT_EXECUTE)
    {
      exec++;
      if (info.protection & VM_PROT_WRITE)
        wx++;
      char path[PROC_PIDPATHINFO_MAXSIZE];
      if (proc_regionfilename(getpid(), addr, path, sizeof(path)) <= 0)
        anon_exec++;
    }
    addr += size;
  }
  fprintf(stderr,
          "JitArm64 AOT VM %s: %u executable regions, %u writable and executable, %u executable "
          "with no file\n",
          label, exec, wx, anon_exec);
#else
  fprintf(stderr, "JitArm64 AOT VM %s: not counted on this platform\n", label);
#endif
}

// The header, as mupen64plus_next's v3 (retro-trainer's `cores/common.sh` aot_meta reads it):
// rom_md5 holds the game's identity (GameIdentity), count_per_op and count_per_op_denom_pot are 0
// (Dolphin's cycle counts are its op table's, in no header field), and the routines' size and
// entry points follow the header.
struct ImageHeader
{
  u32 magic, version, import_count, nblocks;
  u8 core_uuid[16], emit_uuid[16], rom_md5[16];
  u64 imports_hash, layout_hash, abi_hash;
  u32 count_per_op, count_per_op_denom_pot, code_size, reserved;
};
static_assert(sizeof(ImageHeader) == 104, "the header's size is part of IMAGE_VERSION");
constexpr u32 IMAGE_MAGIC = 0x31415452;
constexpr u32 IMAGE_VERSION = 3;

static bool IsZero16(const u8 b[16])
{
  return std::all_of(b, b + 16, [](u8 v) { return v == 0; });
}

// This core build's LC_UUID (from the Mach-O image holding this function); false off Apple, and
// for an all-zero one, which names no build.
static bool SelfUuid(u8 out[16])
{
#ifdef __APPLE__
  Dl_info info{};
  if (!dladdr(reinterpret_cast<const void*>(&SelfUuid), &info) || !info.dli_fbase)
    return false;
  const auto* mh = static_cast<const mach_header_64*>(info.dli_fbase);
  const u8* p = reinterpret_cast<const u8*>(mh + 1);
  for (u32 i = 0; i < mh->ncmds; i++)
  {
    const auto* lc = reinterpret_cast<const load_command*>(p);
    if (lc->cmd == LC_UUID)
    {
      memcpy(out, reinterpret_cast<const uuid_command*>(lc)->uuid, 16);
      return !IsZero16(out);
    }
    p += lc->cmdsize;
  }
#endif
  return false;
}

static bool ParseHex16(const std::string& s, u8 out[16])
{
  int n = 0;
  for (char c : s)
  {
    if (c == '-')
      continue;
    const int v = c >= '0' && c <= '9' ? c - '0' :
                  c >= 'a' && c <= 'f' ? c - 'a' + 10 :
                  c >= 'A' && c <= 'F' ? c - 'A' + 10 :
                                         -1;
    if (v < 0 || n >= 32)
      return false;
    if (n & 1)
      out[n / 2] |= static_cast<u8>(v);
    else
      out[n / 2] = static_cast<u8>(v << 4);
    n++;
  }
  return n == 32 && !IsZero16(out);
}

static std::string Hex16(const u8 b[16])
{
  std::string s;
  char buf[3];
  for (int i = 0; i < 16; i++)
  {
    snprintf(buf, sizeof(buf), "%02X", b[i]);
    s += buf;
    if (i == 3 || i == 5 || i == 7 || i == 9)
      s += '-';
  }
  return s;
}

// The game an image belongs to: its ID and revision, hashed into 16 bytes (two FNV-64s).
static void GameIdentity(u8 out[16])
{
  const std::string id =
      SConfig::GetInstance().GetGameID() + "/" + std::to_string(SConfig::GetInstance().GetRevision());
  // the second hash from another basis, so the two halves differ
  const u64 a = FnvString(id, FNV64_BASIS), b = FnvString(id, ~FNV64_BASIS);
  memcpy(out, &a, 8);
  memcpy(out + 8, &b, 8);
}

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Winvalid-offsetof"
#endif

// Every PowerPCState member the code addresses off PPC_REG, by name, offset and size, the struct's
// size, and the JitBlockData members the dispatcher reads.
static u64 LayoutHash()
{
  u64 h = FNV64_BASIS;
  auto add = [&h](const char* name, size_t off, size_t size) {
    h = FnvString(name, h);
    const u64 v[2] = {off, size};
    h = Fnv64(v, sizeof(v), h);
  };
#define AOT_MEMBER(m) add(#m, offsetof(PowerPC::PowerPCState, m), sizeof(PowerPC::PowerPCState::m));
  AOT_MEMBER(pc) AOT_MEMBER(npc) AOT_MEMBER(stored_stack_pointer) AOT_MEMBER(gather_pipe_ptr)
  AOT_MEMBER(gather_pipe_base_ptr) AOT_MEMBER(gpr) AOT_MEMBER(ps) AOT_MEMBER(cr) AOT_MEMBER(msr)
  AOT_MEMBER(fpscr) AOT_MEMBER(feature_flags) AOT_MEMBER(Exceptions) AOT_MEMBER(downcount)
  AOT_MEMBER(xer_ca) AOT_MEMBER(xer_so_ov) AOT_MEMBER(xer_stringctrl) AOT_MEMBER(reserve_address)
  AOT_MEMBER(reserve) AOT_MEMBER(pagetable_update_pending) AOT_MEMBER(m_enable_dcache)
  AOT_MEMBER(sr) AOT_MEMBER(spr) AOT_MEMBER(mem_ptr) AOT_MEMBER(aot_imports)
#undef AOT_MEMBER
  add("PowerPCState", 0, sizeof(PowerPC::PowerPCState));
  add("JitBlockData::feature_flags", offsetof(JitBlockData, feature_flags), 4);
  add("JitBlockData::effectiveAddress", offsetof(JitBlockData, effectiveAddress), 4);
  add("JitBlockData::normalEntry", offsetof(JitBlockData, normalEntry), 8);
  add("FAST_BLOCK_MAP_FALLBACK_ELEMENTS", JitBaseBlockCache::FAST_BLOCK_MAP_FALLBACK_ELEMENTS, 0);
  return h;
}
}  // namespace JitArm64Aot

using namespace JitArm64Aot;

// The registers and settings a block's code depends on, as they stand in this JIT: the jo flags,
// JitBase's JIT_SETTINGS that change what a block compiles to (the per-category bJIT*Off among
// them), and whether the MMU's address specializations are off (MMU::SetAotForm).
u64 JitArm64::AotAbiHash() const
{
  std::string text = fmt::format(
      "PPC_REG={} MEM_REG={} DISPATCHER_PC={} bAFP={} fastmem={} memcheck={} fp_exceptions={} "
      "div_by_zero={} accurate_single={} gather_pipe={} blocklink={} blr={} branch_follow={} "
      "debug={} profile={} fprf={} accurate_nans={} accurate_fmadds={} dcbz_hack={} "
      "accurate_cache={} page_table_fastmem={} aot_form={} aot_links={}",
      static_cast<int>(PPC_REG), static_cast<int>(MEM_REG), static_cast<int>(DISPATCHER_PC),
      cpu_info.bAFP, jo.fastmem, jo.memcheck, jo.fp_exceptions, jo.div_by_zero_exceptions,
      jo.accurateSinglePrecision, jo.optimizeGatherPipe, jo.enableBlocklink,
      m_enable_blr_optimization, m_enable_branch_following, m_enable_debugging,
      m_enable_profiling, m_fprf, m_accurate_nans, m_accurate_fmadds, m_low_dcbz_hack,
      m_accurate_cpu_cache_enabled, m_page_table_fastmem_enabled, m_mmu.IsAotForm(), LINKS_MAX);
  const bool off[] = {bJITOff,
                      bJITLoadStoreOff,
                      bJITLoadStorelXzOff,
                      bJITLoadStorelwzOff,
                      bJITLoadStorelbzxOff,
                      bJITLoadStoreFloatingOff,
                      bJITLoadStorePairedOff,
                      bJITFloatingPointOff,
                      bJITIntegerOff,
                      bJITPairedOff,
                      bJITSystemRegistersOff,
                      bJITBranchOff,
                      bJITRegisterCacheOff};
  for (bool b : off)
    text += b ? '1' : '0';
  return Fnv64(text.data(), text.size());
}

// Lane-only (retro-trainer HH-34, never for a pinned core): every block dispatch's PC and
// downcount, to DOLPHIN_TRACE_BLOCKS: from shape's dispatcher, and from interp's misses.
static FILE* s_block_trace = [] {
  const char* path = getenv("DOLPHIN_TRACE_BLOCKS");
  return path && *path ? fopen(path, "w") : nullptr;
}();

void JitArm64::AotTraceBlock(u32 pc, s32 downcount, const PowerPC::PowerPCState* ppc)
{
  u64 h = Fnv64(ppc->gpr, sizeof(ppc->gpr));
  h = Fnv64(ppc->ps, sizeof(ppc->ps), h);
  // CR as the guest reads it: JitArm64 and the interpreter encode one field value differently
  // and without its SO bits: JitArm64's compares leave junk in them (cmpl's 64-bit difference
  // sets the encoding's bit 59 whenever LT), the interpreter copies XER.SO
  const u32 more[] = {ppc->cr.Get() & 0xEEEEEEEE, ppc->xer_ca, ppc->xer_so_ov, ppc->fpscr.Hex,
                      ppc->msr.Hex};
  h = Fnv64(more, sizeof(more), h);
  fprintf(s_block_trace, "%08x %d %016" PRIx64 "\n", pc, downcount, h);
  static int full = 0;
  static const u32 full_pc = [] {
    const char* v = getenv("DOLPHIN_TRACE_PC");
    return v ? static_cast<u32>(strtoul(v, nullptr, 16)) : 0u;
  }();
  if (full++ < 3000 || pc == full_pc)
  {
    fprintf(s_block_trace, "  gpr");
    for (u32 r : ppc->gpr)
      fprintf(s_block_trace, " %08x", r);
    fprintf(s_block_trace, "\n  cr %08x ca %x so_ov %x fpscr %08x msr %08x lr %08x ctr %08x\n",
            ppc->cr.Get(), ppc->xer_ca, ppc->xer_so_ov, ppc->fpscr.Hex, ppc->msr.Hex, ppc->spr[SPR_LR],
            ppc->spr[SPR_CTR]);
  }
}

bool JitArm64::AotTracingBlocks()
{
  return s_block_trace != nullptr;
}

const u8** JitArm64::QuantizedTable(int which)
{
  if (m_aot)
    return m_aot->quantized[which].data();
  const u8** table = reinterpret_cast<const u8**>(AlignCode16() + GetWritableRegionDiff());
  ReserveCodeSpace(8 * sizeof(u8*));
  return table;
}

// The routines an image carries, by name, in the order of its entry offsets and of their import
// slots (so their order is in AotImportsHash): the one list of them.
std::span<const JitArm64::AotRoutine> JitArm64::AotRoutines()
{
  static constexpr AotRoutine routines[] = {
      {"enter_code", &JitArm64::enter_code},
      {"dispatcher", &JitArm64::dispatcher},
      {"dispatcher_no_timing_check", &JitArm64::dispatcher_no_timing_check},
      {"dispatcher_no_check", &JitArm64::dispatcher_no_check},
      {"do_timing", &JitArm64::do_timing},
      {"dispatcher_exit", &JitArm64::dispatcher_exit},
      {"fres", &JitArm64::fres},
      {"frsqrte", &JitArm64::frsqrte},
      {"cdts", &JitArm64::cdts},
      {"cstd", &JitArm64::cstd},
      {"fprf_single", &JitArm64::fprf_single},
      {"fprf_double", &JitArm64::fprf_double},
      {"fmadds_eft", &JitArm64::fmadds_eft},
      {"ps_madd_eft", &JitArm64::ps_madd_eft},
  };
  static_assert(std::size(routines) == R_QUANTIZED);
  return routines;
}

// The quantized-routine tables, in the order of their routines' entry offsets (R_QUANTIZED + 8 * t).
std::span<const JitArm64::AotQuantizedTable> JitArm64::AotQuantizedTables()
{
  static constexpr AotQuantizedTable tables[] = {
      &JitArm64::paired_load_quantized, &JitArm64::single_load_quantized,
      &JitArm64::paired_store_quantized, &JitArm64::single_store_quantized};
  static_assert(R_QUANTIZED + 8 * std::size(tables) == R_COUNT);
  return tables;
}

// The import table, in an order every build of this source fixes: the routines (their values set
// once they exist), the quantized-routine tables, the objects and functions the code reaches, and
// every interpreter op FallBackToInterpreter may call, in opcode order.
void JitArm64::AotRegisterImports()
{
  Imports& im = m_aot->imports;
  for (const AotRoutine& r : AotRoutines())
    im.Add(fmt::format("routine:{}", r.name), nullptr);
  for (size_t t = 0; t < AotQuantizedTables().size(); t++)
    im.Add(fmt::format("quantized_table:{}", t), m_aot->quantized[t].data());

  auto& memory = m_system.GetMemory();
  auto obj = [&im](const char* name, const void* p) { im.Add(name, p); };
  auto fn = [&im](const char* name, auto f) { im.Add(name, reinterpret_cast<const void*>(f)); };
  obj("jit", this);
  obj("ppc_state", &m_ppc_state);
  obj("system", &m_system);
  obj("mmu", &m_mmu);
  obj("interpreter", &m_system.GetInterpreter());
  obj("power_pc", &m_system.GetPowerPC());
  obj("gpfifo", &m_system.GetGPFifo());
  obj("jit_interface", &m_system.GetJitInterface());
  obj("cpu_state", m_system.GetCPU().GetStatePtr());
  obj("interrupt_cause", &m_system.GetProcessorInterface().m_interrupt_cause);
  obj("logical_page_mappings", memory.GetLogicalPageMappingsBase());
  obj("physical_page_mappings", memory.GetPhysicalPageMappingsBase());
  obj("fast_block_map_fallback", blocks.GetFastBlockMapFallback());
  obj("block_bitset", blocks.GetBlockBitSet());
  for (u32 g = 0; g < LINKS_GROUPS; g++)
    im.Add(fmt::format("link_table:{}", g), m_aot->link_table.get() + g * LINKS_GROUP);
  obj("dbat_table", m_mmu.GetDBATTable().data());
  obj("ibat_table", m_mmu.GetIBATTable().data());
  obj("core_timing_globals", &m_system.GetCoreTiming().GetGlobals());
  obj("cr_table", PowerPC::ConditionRegister::s_crTable.data());
  obj("fres_expected", &Common::fres_expected);
  obj("frsqrte_expected", &Common::frsqrte_expected);
  obj("quantize_table", &m_quantizeTableS);
  obj("dequantize_table", &m_dequantizeTableS);
  fn("JitTrampoline", &JitTrampoline);
  fn("JitBase::Dispatch", &JitBase::Dispatch);
  fn("CoreTiming::GlobalAdvance", &CoreTiming::GlobalAdvance);
  fn("CoreTiming::GlobalIdle", &CoreTiming::GlobalIdle);
  fn("PowerPC::CheckExceptionsFromJIT", &PowerPC::CheckExceptionsFromJIT);
  fn("PowerPC::CheckExternalExceptionsFromJIT", &PowerPC::CheckExternalExceptionsFromJIT);
  fn("PowerPC::CheckAndHandleBreakPointsFromJIT", &PowerPC::CheckAndHandleBreakPointsFromJIT);
  fn("PowerPC::UpdatePerformanceMonitor", &PowerPC::UpdatePerformanceMonitor);
  fn("PowerPC::RoundingModeUpdated", &PowerPC::RoundingModeUpdated);
  fn("PowerPC::MMU::PageTableUpdatedFromJit", &PowerPC::MMU::PageTableUpdatedFromJit);
  fn("PowerPC::ReadFromJit<u8>", &PowerPC::ReadFromJit<u8>);
  fn("PowerPC::ReadFromJit<u16>", &PowerPC::ReadFromJit<u16>);
  fn("PowerPC::ReadFromJit<u32>", &PowerPC::ReadFromJit<u32>);
  fn("PowerPC::ReadFromJit<u64>", &PowerPC::ReadFromJit<u64>);
  fn("PowerPC::WriteFromJit<u8>", &PowerPC::WriteFromJit<u8>);
  fn("PowerPC::WriteFromJit<u16>", &PowerPC::WriteFromJit<u16>);
  fn("PowerPC::WriteFromJit<u32>", &PowerPC::WriteFromJit<u32>);
  fn("PowerPC::WriteFromJit<u64>", &PowerPC::WriteFromJit<u64>);
  fn("PowerPC::WriteU16SwapFromJit", &PowerPC::WriteU16SwapFromJit);
  fn("PowerPC::WriteU32SwapFromJit", &PowerPC::WriteU32SwapFromJit);
  fn("PowerPC::WriteU64SwapFromJit", &PowerPC::WriteU64SwapFromJit);
  fn("PowerPC::ClearDCacheLineFromJit", &PowerPC::ClearDCacheLineFromJit);
  fn("GPFifo::UpdateGatherPipe", &GPFifo::UpdateGatherPipe);
  fn("GPFifo::FastCheckGatherPipe", &GPFifo::FastCheckGatherPipe);
  fn("HLE::ExecuteFromJIT", &HLE::ExecuteFromJIT);
  fn("JitInterface::CompileExceptionCheckFromJIT", &JitInterface::CompileExceptionCheckFromJIT);
  fn("JitInterface::InvalidateICacheLineFromJIT", &JitInterface::InvalidateICacheLineFromJIT);
  fn("JitInterface::InvalidateICacheLinesFromJIT", &JitInterface::InvalidateICacheLinesFromJIT);

  // Every interpreter op, by the first opcode (primary, then the 10-bit extended field) that
  // selects it.
  for (u32 opcd = 0; opcd < 64; opcd++)
  {
    for (u32 sub = 0; sub < 1024; sub++)
    {
      UGeckoInstruction inst{(opcd << 26) | (sub << 1)};
      const void* f = reinterpret_cast<const void*>(Interpreter::GetInterpreterOp(inst));
      if (f && im.Slot(f) < 0)
        im.Add(fmt::format("interpreter:{}:{}", opcd, sub), f);
    }
  }

  im.base = PPC_REG;
  im.table_offset = PPCSTATE_OFF(aot_imports);
  static_assert(PPCSTATE_OFF(aot_imports) + 8 * PowerPC::PowerPCState::AOT_IMPORT_SLOTS <= 32760,
                "an import slot must be within an LDR's reach of PPC_REG");
}

void JitArm64::AotFillImportTable()
{
  const Imports& im = m_aot->imports;
  for (size_t i = 0; i < im.values.size(); i++)
    m_ppc_state.aot_imports[i] = im.values[i];
}

// The routine pointers and quantized tables GenerateAsm just set, into the routine slots.
void JitArm64::AotRegisterRoutines()
{
  auto& r = m_aot->routines;
  const auto routines = AotRoutines();
  for (size_t i = 0; i < routines.size(); i++)
    r[i] = this->*routines[i].member;
  for (size_t t = 0; t < AotQuantizedTables().size(); t++)
    for (int i = 0; i < 8; i++)
      r[R_QUANTIZED + 8 * t + i] = m_aot->quantized[t][i];
  for (u32 i = 0; i < R_QUANTIZED; i++)
    m_aot->imports.Set(i, r[i]);
  AotFillImportTable();
  m_aot->link_fallback = dispatcher_no_timing_check;
  for (size_t k = 0; k < m_aot->link_keys.size(); k++)
    m_aot->link_table[k] = m_aot->link_fallback;
}

// Routine pointers from an image's entry offsets (load, interp).
void JitArm64::AotBindRoutines(const u8* code, const u32* entries)
{
  auto& r = m_aot->routines;
  for (u32 i = 0; i < R_COUNT; i++)
    r[i] = code + entries[i];
  const auto routines = AotRoutines();
  for (size_t i = 0; i < routines.size(); i++)
    this->*routines[i].member = r[i];
  const auto tables = AotQuantizedTables();
  for (size_t t = 0; t < tables.size(); t++)
  {
    for (int i = 0; i < 8; i++)
      m_aot->quantized[t][i] = r[R_QUANTIZED + 8 * t + i];
    this->*tables[t] = m_aot->quantized[t].data();
  }
  for (u32 i = 0; i < R_QUANTIZED; i++)
    m_aot->imports.Set(i, r[i]);
  AotFillImportTable();
  m_aot->link_fallback = dispatcher_no_timing_check;
  for (size_t k = 0; k < m_aot->link_keys.size(); k++)
    m_aot->link_table[k] = m_aot->link_fallback;
}

// Links. Every exit to a known address (WriteExit) is linked as the JIT links, but through a table
// rather than by patching the exit's code, which an image cannot have written: slot k of the table
// is the exit's (address, feature flags) for every exit that names them, assigned the first time
// a shape run compiles one and logged ("L k ea feature_flags"), so the emit, which compiles from
// the log, gives each the same slot, and the image lists them in slot order. A slot holds its
// block's entry from when the block is compiled (shape) or installed (load, interp) until it is
// destroyed, and otherwise dispatcher_no_timing_check, whose lookup finds, installs or interprets
// it (DISPATCHER_PC holds the address either way). The exit checks the time first, as a linked
// exit does: the dispatcher's code is never between two linked blocks.
void JitArm64::AotAllocLinks()
{
  m_aot->link_table = std::make_unique<const u8*[]>(LINKS_MAX);
}

u32 JitArm64::AotLinkSlot(u32 destination)
{
  const u64 key = static_cast<u64>(m_ppc_state.feature_flags) << 32 | destination;
  if (const auto it = m_aot->link_slot_of.find(key); it != m_aot->link_slot_of.end())
    return it->second;
  if (m_aot->mode != Mode::Shape)
  {
    // emit: a link its log did not name (the emit refuses the image)
    m_aot->stats.link_misses++;
    return UINT32_MAX;
  }
  if (m_aot->link_keys.size() == LINKS_MAX)
    return UINT32_MAX;
  const u32 k = static_cast<u32>(m_aot->link_keys.size());
  m_aot->link_keys.push_back(key);
  m_aot->link_slot_of.emplace(key, k);
  m_aot->link_table[k] = m_aot->link_fallback;
  if (m_aot->log)
    fprintf(m_aot->log, "L %u %08x %x\n", k, destination, m_ppc_state.feature_flags);
  return k;
}

void JitArm64::AotLink(const JitBlock& block)
{
  const u64 key = static_cast<u64>(block.feature_flags) << 32 | block.effectiveAddress;
  if (const auto it = m_aot->link_slot_of.find(key); it != m_aot->link_slot_of.end())
    m_aot->link_table[it->second] = block.normalEntry;
}

// Lane-only (retro-trainer hh34d, never for a pinned core): DOLPHIN_AOT_RED names checks to
// skip, for red receipts: "nounlink" (a destroyed block keeps its link slot), "nofacts" (an image
// block is installed whatever its facts say).
static bool Red(const char* what)
{
  const char* red = getenv("DOLPHIN_AOT_RED");
  return red && strstr(red, what);
}

void JitArm64::AotUnlink(const JitBlock& block)
{
  static const bool red = Red("nounlink");
  if (!m_aot || !m_aot->link_table || red)
    return;
  const u64 key = static_cast<u64>(block.feature_flags) << 32 | block.effectiveAddress;
  if (const auto it = m_aot->link_slot_of.find(key);
      it != m_aot->link_slot_of.end() && m_aot->link_table[it->second] == block.normalEntry)
  {
    m_aot->link_table[it->second] = m_aot->link_fallback;
    m_aot->stats.unlinks++;
  }
}

// Facts. What a block compiles to depends, besides its words and hooks, on a few answers about the
// machine's state when it is compiled: whether a constant address is plain RAM or the gather pipe
// under the BATs (the MMU's IsOptimizable*; a BAT change clears the JIT's blocks), whether a GPR
// looks like a gather pipe constant worth speculating on, and the JIT's history sets
// (noSpeculativeConstantsAddresses, pairedQuantizeAddresses, fifoWriteAddresses). The JIT asks each
// through AotFact. A shape run logs the answers with the block, in the order they were asked; the
// emit answers each from the log, so it compiles the same code; and a load installs a block only
// where every fact it was compiled for holds on the live state (AotFactsHold), as a compile there
// would have answered. Only fifoWriteAddresses' yes answers are kept, one per op at most.
bool JitArm64::AotFact(Fact kind, u32 a, u32 b, bool answer, u32* value)
{
  if (!m_aot)
    return answer;
  auto& facts = m_aot->facts;
  if (m_aot->mode == Mode::Emit && m_aot->emit_facts)
  {
    const std::vector<u32>& logged = *m_aot->emit_facts;
    if (kind == Fact::FifoWrite)
    {
      answer = false;
      for (size_t i = 0; i < logged.size(); i += 4)
        answer |= logged[i] == static_cast<u32>(kind) && logged[i + 1] == a;
    }
    else
    {
      size_t& i = m_aot->emit_fact;
      while (i < logged.size() && logged[i] == static_cast<u32>(Fact::FifoWrite))
        i += 4;
      if (i + 4 > logged.size() || logged[i] != static_cast<u32>(kind) ||
          logged[i + 1] != a || (kind != Fact::Speculate && logged[i + 2] != b))
      {
        m_aot->emit_facts_differ = true;
        return answer;
      }
      answer = logged[i + 3] != 0;
      b = logged[i + 2];
      if (value)
        *value = b;
      i += 4;
    }
  }
  if (kind == Fact::FifoWrite && !answer)
    return false;
  facts.insert(facts.end(), {static_cast<u32>(kind), a, kind == Fact::Speculate && !answer ? 0 : b,
                             static_cast<u32>(answer)});
  return answer;
}

bool JitArm64::AotFactHolds(const u32* f) const
{
  const u32 a = f[1], b = f[2];
  const bool answer = f[3] != 0;
  switch (static_cast<Fact>(f[0]))
  {
  case Fact::Ram:
    return m_mmu.IsOptimizableRAMAddress(a, b) == answer;
  case Fact::GatherPipe:
    return m_mmu.IsOptimizableGatherPipeWrite(a) == answer;
  case Fact::SpeculateGate:
    return !js.noSpeculativeConstantsAddresses.contains(js.blockStart) == answer;
  case Fact::Speculate:
  {
    const u32 v = m_ppc_state.gpr[a];
    return LooksLikeSpeculativeConstant(v) == answer && (!answer || v == b);
  }
  case Fact::PairedQuantize:
    return AssumesNoPairedQuantize() == answer;
  case Fact::FifoWrite:
    return js.fifoWriteAddresses.contains(a) == answer;
  }
  return false;
}

// The image block's facts on the live state, for the block code_block holds (js.blockStart is its
// address): each holds, and no op address the JIT would ask about is in fifoWriteAddresses unless
// the block was compiled with it there.
bool JitArm64::AotFactsHold(const ImageBlock& ib) const
{
  static const bool red = Red("nofacts");
  if (red)
    return true;
  u32 fifo_yes = 0;
  for (u32 i = 0; i < ib.nfacts; i++)
  {
    if (!AotFactHolds(ib.facts + 4 * i))
      return false;
    fifo_yes += ib.facts[4 * i] == static_cast<u32>(Fact::FifoWrite);
  }
  if (js.fifoWriteAddresses.empty())
    return fifo_yes == 0;
  u32 fifo_live = 0;
  for (u32 i = 0; i + 1 < ib.nops; i++)
    fifo_live += js.fifoWriteAddresses.contains(ib.ops[2 * i]);
  return fifo_live == fifo_yes;
}

void JitArm64::AotInit()
{
  const Settings& cfg = GetSettings();
  m_aot = std::make_unique<State>();
  m_aot->mode = cfg.mode;

  // No fastmem arena (InitFastmemArena is not called), so no fastmem (JitBase::RefreshConfig)
  jo.fastmem_arena = false;
  RefreshConfig();

  // shape: the JIT's MAP_JIT cache; emit: plain memory, never executed
  if (cfg.mode == Mode::Shape || cfg.mode == Mode::Emit)
    AllocCodeRegions(cfg.mode == Mode::Shape);

  jo.optimizeGatherPipe = true;
  SetBlockLinkingEnabled(false);
  SetOptimizationEnabled(true);
  gpr.Init(this);
  fpr.Init(this);
  blocks.Init();
  code_block.m_stats = &js.st;
  code_block.m_gpa = &js.gpa;
  code_block.m_fpa = &js.fpa;
  InitBLROptimization();

  AotAllocLinks();
  AotRegisterImports();
  SetAotResolver(&m_aot->imports);

  if (cfg.mode == Mode::Shape || cfg.mode == Mode::Emit)
  {
    GenerateAsmAndResetFreeMemoryRanges();
    if (cfg.mode == Mode::Shape)
    {
      m_aot->log = fopen(cfg.log.c_str(), "w");
      if (!m_aot->log)
      {
        fprintf(stderr, "JitArm64 AOT: cannot write the block log %s\n", cfg.log.c_str());
        std::exit(2);
      }
      fprintf(m_aot->log, "R %zu %016" PRIx64 " %zu %016" PRIx64 " %016" PRIx64 "\n",
              m_aot->routines_size, Fnv64(m_aot->routines_begin, m_aot->routines_size),
              m_aot->imports.names.size(), AotImportsHash(), AotAbiHash());
      fflush(m_aot->log);
      VMReport("at init");
    }
    return;
  }

  // load, interp
  std::string why;
  if (!AotOpenImage(cfg.image, &why))
  {
    const std::string refused = "refused " + cfg.image + ": " + why;
    fprintf(stderr, "JitArm64 AOT: %s\n", refused.c_str());
    Report(false, refused);
    if (cfg.mode == Mode::Load)
    {
      fflush(stderr);
      std::_Exit(4);
    }
    AotStartInterpreter();
    m_aot_refused = true;
    return;
  }
  const std::string admitted =
      fmt::format("admitted {}, {} blocks", cfg.image, m_aot->image_blocks.size());
  fprintf(stderr, "JitArm64 AOT: %s\n", admitted.c_str());
  Report(true, admitted);
  if (cfg.mode == Mode::Interp)
    AotStartInterpreter();
  VMReport("at image load");
}

u64 JitArm64::AotImportsHash() const
{
  u64 h = FNV64_BASIS;
  for (const std::string& name : m_aot->imports.names)
    h = FnvString(name, h);
  return h;
}

void JitArm64::AotStartInterpreter()
{
  m_aot_ci = std::make_unique<CachedInterpreter>(m_system);
  m_aot_ci->SetJitTiming(this);
  m_aot_ci->Init();
  blocks.SetShadowCache(m_aot_ci->GetBlockCache());
}

// The routines GenerateAsm just made: where they start and how long they are.
void JitArm64::AotRoutinesGenerated(const u8* begin, const u8* end)
{
  m_aot->routines_begin = begin;
  m_aot->routines_size = static_cast<size_t>(end - begin);
  AotRegisterRoutines();
}

// `core_uuid`: the loading build's LC_UUID, or null for this build's own. False when this build
// has no LC_UUID (off Apple): no image may name it.
bool JitArm64::AotHeader(u8* out, u32 nblocks, u32 code_size, const u8* core_uuid) const
{
  ImageHeader h{};
  h.magic = IMAGE_MAGIC;
  h.version = IMAGE_VERSION;
  h.import_count = static_cast<u32>(m_aot->imports.names.size());
  h.nblocks = nblocks;
  const bool ok = SelfUuid(h.emit_uuid);
  memcpy(h.core_uuid, core_uuid ? core_uuid : h.emit_uuid, 16);
  GameIdentity(h.rom_md5);
  h.imports_hash = AotImportsHash();
  h.layout_hash = LayoutHash();
  h.abi_hash = AotAbiHash();
  h.code_size = code_size;
  memcpy(out, &h, sizeof(h));
  return ok;
}

bool JitArm64::AotOpenImage(const std::string& path, std::string* why)
{
#ifdef _WIN32
  *why = "images are dylibs, which this platform does not open";
  return false;
#else
  void* handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
  if (!handle)
  {
    *why = fmt::format("dlopen: {}", dlerror());
    return false;
  }
  const auto* code = static_cast<const u8*>(dlsym(handle, "rt_aot_code"));
  const auto* code_end = static_cast<const u8*>(dlsym(handle, "rt_aot_code_end"));
  const auto* meta = static_cast<const u8*>(dlsym(handle, "rt_aot_meta"));
  const auto* meta_end = static_cast<const u8*>(dlsym(handle, "rt_aot_meta_end"));
  auto refuse = [&](std::string text) {
    *why = std::move(text);
    dlclose(handle);
    return false;
  };
  if (!code || !code_end || !meta || !meta_end ||
      meta_end - meta < static_cast<ptrdiff_t>(sizeof(ImageHeader)))
  {
    return refuse("symbols: no rt_aot_code..rt_aot_code_end and rt_aot_meta..rt_aot_meta_end");
  }

  ImageHeader got, want;
  memcpy(&got, meta, sizeof(got));
  u8 want_bytes[sizeof(ImageHeader)];
  if (!AotHeader(want_bytes, got.nblocks, static_cast<u32>(code_end - code), nullptr))
    return refuse("core_uuid: this core build has no LC_UUID to check the image's against");
  memcpy(&want, want_bytes, sizeof(want));
#define AOT_FIELD(f)                                                                               \
  if (got.f != want.f)                                                                             \
    return refuse(fmt::format(#f ": the image has {:#x}, this core {:#x}", static_cast<u64>(got.f), \
                              static_cast<u64>(want.f)));
#define AOT_BYTES(f)                                                                               \
  if (memcmp(got.f, want.f, 16))                                                                   \
    return refuse(fmt::format(#f ": the image has {}, this core {}", Hex16(got.f), Hex16(want.f)));
  AOT_FIELD(magic)
  AOT_FIELD(version)
  AOT_BYTES(core_uuid)
  AOT_FIELD(import_count)
  AOT_FIELD(imports_hash)
  AOT_FIELD(layout_hash)
  AOT_FIELD(abi_hash)
  AOT_BYTES(rom_md5)
  AOT_FIELD(count_per_op)
  AOT_FIELD(count_per_op_denom_pot)
  AOT_FIELD(code_size)
#undef AOT_FIELD
#undef AOT_BYTES

  const u32* w = reinterpret_cast<const u32*>(meta + sizeof(ImageHeader));
  const u32* end = reinterpret_cast<const u32*>(meta_end);
  if (end - w < 2 + static_cast<ptrdiff_t>(R_COUNT) || w[1] != R_COUNT || w[0] > got.code_size)
    return refuse("routines: not this core's routine table");
  const u32 routines_size = w[0];
  const u32* entries = w + 2;
  for (u32 i = 0; i < R_COUNT; i++)
    if (entries[i] >= routines_size)
      return refuse(fmt::format("routines: entry {} at {:#x} is past their end", i, entries[i]));
  w = entries + R_COUNT;
  if (end - w < 1 || static_cast<u64>(end - w - 1) < 2ULL * w[0] || w[0] > LINKS_MAX)
    return refuse("links: the meta ends inside the link table, or it is past LINKS_MAX");
  const u32 nlinks = *w++;
  m_aot->link_keys.clear();
  m_aot->link_slot_of.clear();
  for (u32 k = 0; k < nlinks; k++, w += 2)
  {
    const u64 key = static_cast<u64>(w[1]) << 32 | w[0];
    if (!m_aot->link_slot_of.emplace(key, k).second)
      return refuse(fmt::format("links: link {} ({:08x}) is listed twice", k, w[0]));
    m_aot->link_keys.push_back(key);
  }
  m_aot->image_blocks.clear();
  for (u32 i = 0; i < got.nblocks; i++)
  {
    if (end - w < 7)
      return refuse(fmt::format("blocks: the meta ends inside block {}", i));
    ImageBlock b{w[0], w[1], w[2], w[3], w[4], w[5], w[6], w + 7, nullptr, nullptr};
    if (static_cast<u64>(end - b.ops) < 2ULL * b.nops + 2ULL * b.nhooks + 4ULL * b.nfacts ||
        static_cast<u64>(b.code_off) + b.code_len > got.code_size || b.code_off < routines_size)
      return refuse(fmt::format("blocks: block {} ({:08x}) is out of bounds", i, b.ea));
    b.hooks = b.ops + 2 * b.nops;
    b.facts = b.hooks + 2 * b.nhooks;
    m_aot->image_blocks.emplace(static_cast<u64>(b.feature_flags) << 32 | b.ea, b);
    w = b.facts + 4 * b.nfacts;
  }
  m_aot->image_handle = handle;
  m_aot->image_code = code;
  m_aot->image_code_size = static_cast<size_t>(code_end - code);
  blocks.SetImageCode(code, code_end);
  AotBindRoutines(code, entries);
  return true;
#endif
}

// A block the dispatcher did not find: install the image's block for it when its ops are the
// analyzer's on live memory; otherwise load stops, and interp runs it on the Cached Interpreter.
void JitArm64::AotMiss(u32 em_address)
{
  if (s_block_trace)
    AotTraceBlock(em_address, m_ppc_state.downcount, &m_ppc_state);
  // A block the Cached Interpreter holds already missed the image when it was first reached
  if (m_aot_ci && m_aot_ci->AotHasBlock())
  {
    m_aot->stats.interp_blocks++;
    m_aot_ci->AotExecuteOneBlock();
    return;
  }
  const u32 nextPC = analyzer.Analyze(em_address, &code_block, &m_code_buffer, m_code_buffer.size());
  if (code_block.m_memory_exception)
  {
    m_ppc_state.npc = nextPC;
    m_ppc_state.Exceptions |= EXCEPTION_ISI;
    m_system.GetPowerPC().CheckExceptions();
    m_system.GetJitInterface().UpdateMembase();
    return;
  }
  const u64 key = static_cast<u64>(m_ppc_state.feature_flags) << 32 | em_address;
  const auto [lo, hi] = m_aot->image_blocks.equal_range(key);
  const std::vector<u32> hooks = lo == hi ? std::vector<u32>{} : AotBlockHooks();
  for (auto it = lo; it != hi; ++it)
  {
    const ImageBlock& ib = it->second;
    if (ib.nops != code_block.m_num_instructions || 2 * ib.nhooks != hooks.size() ||
        !std::equal(hooks.begin(), hooks.end(), ib.hooks))
      continue;
    bool same = true;
    for (u32 i = 0; i < ib.nops && same; i++)
      same = ib.ops[2 * i] == m_code_buffer[i].address && ib.ops[2 * i + 1] == m_code_buffer[i].inst.hex;
    if (!same)
      continue;
    js.blockStart = em_address;
    if (!AotFactsHold(ib))
    {
      m_aot->stats.fact_refusals++;
      continue;
    }
    JitBlock* b = blocks.AllocateBlock(em_address);
    b->normalEntry = const_cast<u8*>(m_aot->image_code + ib.code_off);
    b->near_begin = b->near_end = b->far_begin = b->far_end = nullptr;
    blocks.FinalizeBlock(*b, false, code_block, m_code_buffer);
    AotLink(*b);
    m_aot->stats.installs++;
    return;
  }
  m_aot->stats.misses++;
  if (m_aot->mode == Mode::Load)
  {
    fprintf(stderr, "JitArm64 AOT: miss at %08x (feature flags %x)\n", em_address,
            m_ppc_state.feature_flags);
    AotReport();
    fflush(stderr);
    std::_Exit(5);  // from the CPU thread: no static destructors under the other threads
  }
  m_aot->stats.interp_blocks++;
  m_aot_ci->AotExecuteOneBlock();
}

// The HLE hooks at the ops of the block just analyzed: (address, hook index) pairs.
std::vector<u32> JitArm64::AotBlockHooks() const
{
  std::vector<u32> hooks;
  for (u32 i = 0; i < code_block.m_num_instructions; i++)
  {
    const u32 address = m_code_buffer[i].address;
    if (const u32 index = HLE::GetHookByFunctionAddress(m_ppc_symbol_db, address))
      hooks.insert(hooks.end(), {address, index});
  }
  return hooks;
}

// A block's code as hex words, to stderr (DOLPHIN_AOT_CORRUPT names it in a shape run, which
// changes nothing there; a diagnostic for a block an emit says differs).
void JitArm64::AotDumpCode(const char* what, const u8* code, size_t len)
{
  fprintf(stderr, "JitArm64 AOT code %s:", what);
  for (size_t i = 0; i + 4 <= len; i += 4)
  {
    u32 inst;
    memcpy(&inst, code + i, 4);
    fprintf(stderr, " %08x", inst);
  }
  fputc('\n', stderr);
}

// shape: one compiled block's record.
void JitArm64::AotLogBlock(const JitBlock& b)
{
  m_aot->stats.compiled++;
  const u8* code = b.normalEntry;
  const size_t len = static_cast<size_t>(b.near_end - b.normalEntry);
  if (m_aot->imports.unresolved_in_unit)
    m_aot->stats.unresolved_blocks++;
  const std::vector<u32> hooks = AotBlockHooks();
  const std::vector<u32>& facts = m_aot->facts;
  fprintf(m_aot->log, "B %08x %x %u %zu %016" PRIx64 " %u %zu %zu", b.effectiveAddress,
          b.feature_flags, code_block.m_num_instructions, len, Fnv64(code, len),
          m_aot->imports.unresolved_in_unit, hooks.size() / 2, facts.size() / 4);
  for (u32 i = 0; i < code_block.m_num_instructions; i++)
    fprintf(m_aot->log, " %08x:%08x", m_code_buffer[i].address, m_code_buffer[i].inst.hex);
  for (size_t i = 0; i < hooks.size(); i += 2)
    fprintf(m_aot->log, " %08x:%x", hooks[i], hooks[i + 1]);
  for (size_t i = 0; i < facts.size(); i += 4)
    fprintf(m_aot->log, " %x:%08x:%x:%x", facts[i], facts[i + 1], facts[i + 2], facts[i + 3]);
  fputc('\n', m_aot->log);
  if (GetSettings().corrupt == b.effectiveAddress)
    AotDumpCode("shape", code, len);
}

void JitArm64::AotReport()
{
  const auto& s = m_aot->stats;
  fprintf(stderr,
          "JitArm64 AOT stats: %" PRIu64 " compiled (%" PRIu64 " with an unresolved host address), %" PRIu64
          " installed, %" PRIu64 " missed, %" PRIu64 " interpreted; %zu links, %" PRIu64
          " unlinked; %" PRIu64 " image blocks whose facts did not hold\n",
          s.compiled, s.unresolved_blocks, s.installs, s.misses, s.interp_blocks,
          m_aot->link_keys.size(), s.unlinks, s.fact_refusals);
}

void JitArm64::AotShutdown()
{
  m_mmu.SetAotForm(false);
  AotReport();
  VMReport("at end of run");
  if (m_aot->log)
    fclose(m_aot->log);
  if (m_aot_ci)
  {
    blocks.SetShadowCache(nullptr);
    m_aot_ci->Shutdown();
    m_aot_ci.reset();
  }
}

// emit: compile each distinct logged block from its logged words, check it against the shape
// run's, write the image, and exit (0, or 3 when a block differs or holds a host address).
void JitArm64::AotEmit()
{
  const Settings& cfg = GetSettings();
  std::ifstream in(cfg.log);
  if (!in)
  {
    fprintf(stderr, "JitArm64 AOT emit: cannot read %s\n", cfg.log.c_str());
    std::exit(2);
  }
  struct Rec
  {
    u32 ea, ff, nops;
    size_t len;
    u64 hash;
    u32 unresolved, nhooks, nfacts;
    std::vector<u32> ops, hooks, facts;
  };
  std::vector<Rec> recs;
  std::map<std::tuple<u32, u32, std::vector<u32>, std::vector<u32>, std::vector<u32>>, size_t> seen;
  u32 dup_differs = 0, routines_differ = 0, malformed = 0, r_lines = 0, line_no = 0;
  std::string line;
  // Each line whole: a record cut short (a shape run that did not end) or with anything after its
  // fields is malformed, never read as far as it goes.
  auto parse_record = [](const char* p, Rec* r) {
    int n = 0;
    if (sscanf(p, "B %x %x %u %zu %" SCNx64 " %u %u %u%n", &r->ea, &r->ff, &r->nops, &r->len,
               &r->hash, &r->unresolved, &r->nhooks, &r->nfacts, &n) != 8)
      return false;
    p += n;
    auto pairs = [&p](std::vector<u32>* out, u32 count) {
      out->resize(2 * static_cast<size_t>(count));
      for (u32 i = 0; i < count; i++)
      {
        int m = 0;
        if (sscanf(p, " %x:%x%n", &(*out)[2 * i], &(*out)[2 * i + 1], &m) != 2)
          return false;
        p += m;
      }
      return true;
    };
    if (!pairs(&r->ops, r->nops) || !pairs(&r->hooks, r->nhooks))
      return false;
    r->facts.resize(4 * static_cast<size_t>(r->nfacts));
    for (u32 i = 0; i < r->nfacts; i++)
    {
      int m = 0;
      u32* f = &r->facts[4 * i];
      if (sscanf(p, " %x:%x:%x:%x%n", &f[0], &f[1], &f[2], &f[3], &m) != 4)
        return false;
      p += m;
    }
    return strspn(p, " \r") == strlen(p);
  };
  while (std::getline(in, line))
  {
    line_no++;
    if (line.starts_with("L "))
    {
      u32 k, ea, ff;
      int n = 0;
      if (sscanf(line.c_str(), "L %u %x %x%n", &k, &ea, &ff, &n) != 3 ||
          strspn(line.c_str() + n, " \r") != line.size() - n || k != m_aot->link_keys.size() ||
          !m_aot->link_slot_of.emplace(static_cast<u64>(ff) << 32 | ea, k).second)
      {
        fprintf(stderr, "JitArm64 AOT emit: line %u: a malformed or out-of-order L line\n", line_no);
        malformed++;
        continue;
      }
      m_aot->link_keys.push_back(static_cast<u64>(ff) << 32 | ea);
      continue;
    }
    if (line.starts_with("R "))
    {
      size_t size, nimports;
      u64 hash, ihash, ahash;
      int n = 0;
      r_lines++;
      if (sscanf(line.c_str(), "R %zu %" SCNx64 " %zu %" SCNx64 " %" SCNx64 "%n", &size, &hash,
                 &nimports, &ihash, &ahash, &n) != 5 ||
          strspn(line.c_str() + n, " \r") != line.size() - n)
      {
        fprintf(stderr, "JitArm64 AOT emit: line %u: a malformed R line\n", line_no);
        malformed++;
      }
      else if (size != m_aot->routines_size || hash != Fnv64(m_aot->routines_begin, size) ||
               nimports != m_aot->imports.names.size() || ihash != AotImportsHash() ||
               ahash != AotAbiHash())
      {
        fprintf(stderr, "JitArm64 AOT emit: the routines or imports differ from the shape run's\n");
        routines_differ++;
      }
      continue;
    }
    Rec r;
    if (!parse_record(line.c_str(), &r))
    {
      fprintf(stderr, "JitArm64 AOT emit: line %u: not a whole R or B record\n", line_no);
      malformed++;
      continue;
    }
    auto [it, fresh] =
        seen.emplace(std::make_tuple(r.ea, r.ff, r.ops, r.hooks, r.facts), recs.size());
    if (!fresh)
    {
      if (recs[it->second].hash != r.hash || recs[it->second].len != r.len)
        dup_differs++;
      continue;
    }
    recs.push_back(std::move(r));
  }
  // The R line is what ties the log to this build's routines and imports: a log without one is
  // checked against nothing
  if (r_lines != 1)
  {
    fprintf(stderr, "JitArm64 AOT emit: the log has %u R lines, not 1\n", r_lines);
    malformed++;
  }

  std::vector<u8> code(m_aot->routines_begin, m_aot->routines_begin + m_aot->routines_size);
  std::vector<u32> meta_blocks;
  u32 differs = 0, unresolved = 0, failed = 0;
  const u32 saved_ff = m_ppc_state.feature_flags;
  for (const Rec& r : recs)
  {
    std::unordered_map<u32, u32> words, hooks;
    for (u32 i = 0; i < r.nops; i++)
      words.emplace(r.ops[2 * i], r.ops[2 * i + 1]);
    for (u32 i = 0; i < r.nhooks; i++)
      hooks.emplace(r.hooks[2 * i], r.hooks[2 * i + 1]);
    m_ppc_state.feature_flags = static_cast<CPUEmuFeatureFlags>(r.ff);
    m_mmu.SetAotFetchOverride(&words);
    HLE::SetAotHookOverride(&hooks);
    m_aot_last_block = nullptr;
    m_aot->emit_facts = &r.facts;
    m_aot->emit_fact = 0;
    m_aot->emit_facts_differ = false;
    Jit(r.ea, false);
    m_aot->emit_facts = nullptr;
    // every fact the compile asked was the log's, in order, and it asked them all
    const bool facts_differ = m_aot->emit_facts_differ || m_aot->facts != r.facts;
    m_mmu.SetAotFetchOverride(nullptr);
    HLE::SetAotHookOverride(nullptr);
    const JitBlock* b = m_aot_last_block;
    if (!b)
    {
      fprintf(stderr, "JitArm64 AOT emit: %08x did not compile\n", r.ea);
      failed++;
      continue;
    }
    u8* bcode = b->normalEntry;
    const size_t len = static_cast<size_t>(b->near_end - b->normalEntry);
    if (cfg.corrupt == r.ea)
    {
      // ADD (immediate, 32-bit): its immediate +1, the red receipt's one wrong instruction
      for (size_t i = 0; i + 4 <= len; i += 4)
      {
        u32 inst;
        memcpy(&inst, bcode + i, 4);
        if ((inst & 0xFF800000) == 0x11000000 && ((inst >> 10) & 0xFFF) < 0xFFF)
        {
          inst += 1 << 10;
          memcpy(bcode + i, &inst, 4);
          fprintf(stderr, "JitArm64 AOT emit: corrupted %08x at +%zu\n", r.ea, i);
          break;
        }
      }
    }
    else if (len != r.len || Fnv64(bcode, len) != r.hash || m_aot->imports.unresolved_in_unit ||
             r.unresolved || facts_differ)
    {
      AotDumpCode("emit", bcode, len);
      if (m_aot->imports.unresolved_in_unit || r.unresolved)
        unresolved++;
      else
        differs++;
      fprintf(stderr, "JitArm64 AOT emit: %08x differs (%zu bytes against %zu%s)\n", r.ea, len,
              r.len, facts_differ ? "; its facts differ" : "");
    }
    const u32 off = static_cast<u32>(code.size());
    code.insert(code.end(), bcode, bcode + len);
    meta_blocks.insert(meta_blocks.end(),
                       {r.ea, r.ff, r.nops, r.nhooks, r.nfacts, off, static_cast<u32>(len)});
    meta_blocks.insert(meta_blocks.end(), r.ops.begin(), r.ops.end());
    meta_blocks.insert(meta_blocks.end(), r.hooks.begin(), r.hooks.end());
    meta_blocks.insert(meta_blocks.end(), r.facts.begin(), r.facts.end());
  }
  m_ppc_state.feature_flags = static_cast<CPUEmuFeatureFlags>(saved_ff);

  std::vector<u8> meta(sizeof(ImageHeader));
  u8 core_uuid[16];
  if ((!cfg.core_uuid.empty() && !ParseHex16(cfg.core_uuid, core_uuid)) ||
      !AotHeader(meta.data(), static_cast<u32>(recs.size()), static_cast<u32>(code.size()),
                 cfg.core_uuid.empty() ? nullptr : core_uuid))
  {
    fprintf(stderr, "JitArm64 AOT emit: no LC_UUID, or DOLPHIN_AOT_CORE_UUID is not one\n");
    std::exit(2);
  }
  std::vector<u32> body = {static_cast<u32>(m_aot->routines_size), R_COUNT};
  for (u32 i = 0; i < R_COUNT; i++)
    body.push_back(static_cast<u32>(m_aot->routines[i] - m_aot->routines_begin));
  body.push_back(static_cast<u32>(m_aot->link_keys.size()));
  for (const u64 key : m_aot->link_keys)
    body.insert(body.end(), {static_cast<u32>(key), static_cast<u32>(key >> 32)});
  body.insert(body.end(), meta_blocks.begin(), meta_blocks.end());
  const u8* bb = reinterpret_cast<const u8*>(body.data());
  meta.insert(meta.end(), bb, bb + 4 * body.size());

  const std::string code_path = cfg.image + ".code", meta_path = cfg.image + ".meta";
  remove(code_path.c_str());
  remove(meta_path.c_str());
  if (m_aot->stats.link_misses)
    fprintf(stderr, "JitArm64 AOT emit: %" PRIu64 " exits to a link the log does not name\n",
            m_aot->stats.link_misses);
  const bool bad = differs || unresolved || failed || dup_differs || routines_differ || malformed ||
                   m_aot->stats.link_misses;
  fprintf(stderr,
          "JitArm64 AOT emit: %zu blocks (%u duplicate records compiled differently, %u malformed "
          "lines), %zu bytes of code (routines %zu); %u differ from the shape run's, %u hold a "
          "host address, %u failed\n",
          recs.size(), dup_differs, malformed, code.size(), m_aot->routines_size, differs,
          unresolved, failed);
  if (!bad || cfg.corrupt)
  {
    FILE* c = fopen(code_path.c_str(), "wb");
    FILE* m = fopen(meta_path.c_str(), "wb");
    if (!c || !m || fwrite(code.data(), 1, code.size(), c) != code.size() ||
        fwrite(meta.data(), 1, meta.size(), m) != meta.size())
    {
      fprintf(stderr, "JitArm64 AOT emit: cannot write %s\n", cfg.image.c_str());
      std::_Exit(2);
    }
    fclose(c);
    fclose(m);
    fprintf(stderr, "JitArm64 AOT emit: wrote %s and %s\n", code_path.c_str(), meta_path.c_str());
  }
  fflush(stderr);
  std::_Exit(bad && !cfg.corrupt ? 3 : 0);
}
