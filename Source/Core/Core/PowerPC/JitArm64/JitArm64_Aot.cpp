// Copyright 2026 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

// JitArm64's AOT form: the modes are JitArm64_Aot.h's. This file is the image format's one home.
//
// An image is <prefix>.code and <prefix>.meta, linked into one dylib by retro-trainer's
// `cores/cores.sh aot link` (the code in __TEXT,__text between rt_aot_code and rt_aot_code_end,
// the meta in __TEXT,__const between rt_aot_meta and rt_aot_meta_end). The code is the shared
// routines (GenerateAsm's, AOT-shaped), from offset 0, then the blocks. The meta, little-endian, is
// ImageHeader, then u32 words: the routines' size, R_COUNT, the routine entry offsets
// (JitArm64Aot::Routine order), then per block
//   ea, feature_flags, nops, nhooks, code_off, code_len, ops[2 * nops] (each op's address and
//   word), hooks[2 * nhooks] (each op address HLE hooks, and its hook index),
// the ops in the order the analyzer left them. A block's key is its address, feature flags, ops and
// hooks: the hooks are the game's symbol state where it was compiled (HLE::GetHookByFunctionAddress),
// which changes as the game runs, and they change the code. A load refuses an image unless each checked header
// field is this core's (CheckHeader names the first that differs, with both values); a block is
// installed only where the analyzer, run on live memory, gives exactly its ops.

#include "Core/PowerPC/JitArm64/JitArm64_Aot.h"

#include <algorithm>
#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <map>
#include <set>
#include <unistd.h>

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
static std::string s_outcome;

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

const std::string& LastOutcome()
{
  return s_outcome;
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
    Dl_info info{};
    const char* sym = dladdr(target, &info) && info.dli_sname ? info.dli_sname : "?";
    const uintptr_t base = reinterpret_cast<uintptr_t>(info.dli_fbase);
    fprintf(stderr, "JitArm64 AOT: unresolved %s %p (%s, image offset %#" PRIxPTR ")\n", what,
            target, sym, base ? reinterpret_cast<uintptr_t>(target) - base : 0);
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

// This core build's LC_UUID (from the Mach-O image holding this function); false off Apple.
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
      return true;
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
  return n == 32;
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
  const u64 a = FnvString(id, 0xcbf29ce484222325ULL), b = FnvString(id, 0x84222325cbf29ce4ULL);
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
  u64 h = 0xcbf29ce484222325ULL;
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

// The registers and options the code shape depends on, and the JIT settings (JitBase's
// JIT_SETTINGS, the jo flags), as they stand in this JIT.
u64 JitArm64::AotAbiHash() const
{
  std::string text = fmt::format(
      "PPC_REG={} MEM_REG={} DISPATCHER_PC={} bAFP={} fastmem={} memcheck={} fp_exceptions={} "
      "div_by_zero={} accurate_single={} gather_pipe={} blocklink={} blr={} branch_follow={} "
      "debug={} profile={} fprf={} accurate_nans={} accurate_fmadds={} dcbz_hack={} "
      "accurate_cache={} regcache_off={}",
      static_cast<int>(PPC_REG), static_cast<int>(MEM_REG), static_cast<int>(DISPATCHER_PC),
      cpu_info.bAFP, jo.fastmem, jo.memcheck, jo.fp_exceptions, jo.div_by_zero_exceptions,
      jo.accurateSinglePrecision, jo.optimizeGatherPipe, jo.enableBlocklink,
      m_enable_blr_optimization, m_enable_branch_following, m_enable_debugging,
      m_enable_profiling, m_fprf, m_accurate_nans, m_accurate_fmadds, m_low_dcbz_hack,
      m_accurate_cpu_cache_enabled, bJITRegisterCacheOff);
  return Fnv64(text.data(), text.size());
}

void JitArm64::AotMissTrampoline(JitArm64& jit, u32 em_address)
{
  if (jit.m_aot->mode == Mode::Load || jit.m_aot->mode == Mode::Interp)
    jit.AotMiss(em_address);
  else
    jit.Jit(em_address);
}

const u8** JitArm64::AotQuantizedTable(int which)
{
  return m_aot->quantized[which].data();
}

// The import table, in an order every build of this source fixes: the routines (their values set
// once they exist), the quantized-routine tables, the objects and functions the code reaches, and
// every interpreter op FallBackToInterpreter may call, in opcode order.
void JitArm64::AotRegisterImports()
{
  Imports& im = m_aot->imports;
  static const char* routine_names[] = {
      "enter_code", "dispatcher", "dispatcher_no_timing_check", "dispatcher_no_check",
      "do_timing",  "dispatcher_exit", "fres", "frsqrte", "cdts", "cstd", "fprf_single",
      "fprf_double", "fmadds_eft", "ps_madd_eft"};
  static_assert(std::size(routine_names) == R_QUANTIZED);
  for (const char* name : routine_names)
    im.Add(fmt::format("routine:{}", name), nullptr);
  for (int t = 0; t < 4; t++)
    im.Add(fmt::format("quantized_table:{}", t), m_aot->quantized[t].data());

  auto& memory = m_system.GetMemory();
  auto obj = [&im](const char* name, const void* p) { im.Add(name, p); };
  auto fn = [&im](const char* name, auto f) { im.Add(name, reinterpret_cast<const void*>(f)); };
  obj("jit", this);
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
  obj("dbat_table", m_mmu.GetDBATTable().data());
  obj("ibat_table", m_mmu.GetIBATTable().data());
  obj("core_timing_globals", &m_system.GetCoreTiming().GetGlobals());
  obj("cr_table", PowerPC::ConditionRegister::s_crTable.data());
  obj("fres_expected", &Common::fres_expected);
  obj("frsqrte_expected", &Common::frsqrte_expected);
  obj("quantize_table", &m_quantizeTableS);
  obj("dequantize_table", &m_dequantizeTableS);
  fn("aot_miss", &JitArm64::AotMissTrampoline);
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
  r[R_ENTER_CODE] = enter_code;
  r[R_DISPATCHER] = dispatcher;
  r[R_DISPATCHER_NO_TIMING_CHECK] = dispatcher_no_timing_check;
  r[R_DISPATCHER_NO_CHECK] = dispatcher_no_check;
  r[R_DO_TIMING] = do_timing;
  r[R_DISPATCHER_EXIT] = dispatcher_exit;
  r[R_FRES] = fres;
  r[R_FRSQRTE] = frsqrte;
  r[R_CDTS] = cdts;
  r[R_CSTD] = cstd;
  r[R_FPRF_SINGLE] = fprf_single;
  r[R_FPRF_DOUBLE] = fprf_double;
  r[R_FMADDS_EFT] = fmadds_eft;
  r[R_PS_MADD_EFT] = ps_madd_eft;
  for (int t = 0; t < 4; t++)
    for (int i = 0; i < 8; i++)
      r[R_QUANTIZED + 8 * t + i] = m_aot->quantized[t][i];
  for (int i = 0; i < R_QUANTIZED; i++)
    m_aot->imports.Set(i, r[i]);
  AotFillImportTable();
}

// Routine pointers from an image's entry offsets (load, interp).
void JitArm64::AotBindRoutines(const u8* code, const u32* entries)
{
  auto& r = m_aot->routines;
  for (int i = 0; i < R_COUNT; i++)
    r[i] = code + entries[i];
  enter_code = r[R_ENTER_CODE];
  dispatcher = r[R_DISPATCHER];
  dispatcher_no_timing_check = r[R_DISPATCHER_NO_TIMING_CHECK];
  dispatcher_no_check = r[R_DISPATCHER_NO_CHECK];
  do_timing = r[R_DO_TIMING];
  dispatcher_exit = r[R_DISPATCHER_EXIT];
  fres = r[R_FRES];
  frsqrte = r[R_FRSQRTE];
  cdts = r[R_CDTS];
  cstd = r[R_CSTD];
  fprf_single = r[R_FPRF_SINGLE];
  fprf_double = r[R_FPRF_DOUBLE];
  fmadds_eft = r[R_FMADDS_EFT];
  ps_madd_eft = r[R_PS_MADD_EFT];
  for (int t = 0; t < 4; t++)
    for (int i = 0; i < 8; i++)
      m_aot->quantized[t][i] = r[R_QUANTIZED + 8 * t + i];
  paired_load_quantized = m_aot->quantized[0].data();
  single_load_quantized = m_aot->quantized[1].data();
  paired_store_quantized = m_aot->quantized[2].data();
  single_store_quantized = m_aot->quantized[3].data();
  for (int i = 0; i < R_QUANTIZED; i++)
    m_aot->imports.Set(i, r[i]);
  AotFillImportTable();
}

void JitArm64::AotInit()
{
  const Settings& cfg = GetSettings();
  m_aot = std::make_unique<State>();
  m_aot->mode = cfg.mode;
  m_aot_form = true;

  jo.fastmem_arena = false;
  RefreshConfig();

  // shape: the JIT's MAP_JIT cache; emit: plain memory, never executed
  if (cfg.mode == Mode::Shape || cfg.mode == Mode::Emit)
    AllocCodeRegions(cfg.mode == Mode::Shape);

  jo.optimizeGatherPipe = false;
  SetBlockLinkingEnabled(false);
  SetOptimizationEnabled(true);
  gpr.Init(this);
  fpr.Init(this);
  blocks.Init();
  code_block.m_stats = &js.st;
  code_block.m_gpa = &js.gpa;
  code_block.m_fpa = &js.fpa;
  InitBLROptimization();

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
    s_outcome = "refused " + cfg.image + ": " + why;
    fprintf(stderr, "JitArm64 AOT: %s\n", s_outcome.c_str());
    if (cfg.mode == Mode::Load)
    {
      fflush(stderr);
      std::_Exit(4);
    }
    AotStartInterpreter();
    m_aot_refused = true;
    return;
  }
  s_outcome = "admitted " + cfg.image;
  fprintf(stderr, "JitArm64 AOT: %s, %zu blocks\n", s_outcome.c_str(),
          m_aot->image_blocks.size());
  if (cfg.mode == Mode::Interp)
    AotStartInterpreter();
  VMReport("at image load");
}

u64 JitArm64::AotImportsHash() const
{
  u64 h = 0xcbf29ce484222325ULL;
  for (const std::string& name : m_aot->imports.names)
    h = FnvString(name, h);
  return h;
}

void JitArm64::AotStartInterpreter()
{
  m_aot_ci = std::make_unique<CachedInterpreter>(m_system);
  m_aot_ci->SetJitTimed(true, &JitArm64::AotExitKind);
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

bool JitArm64::AotHeader(u8* out, u32 nblocks, u32 code_size, const std::string& core_uuid) const
{
  ImageHeader h{};
  h.magic = IMAGE_MAGIC;
  h.version = IMAGE_VERSION;
  h.import_count = static_cast<u32>(m_aot->imports.names.size());
  h.nblocks = nblocks;
  bool ok = SelfUuid(h.emit_uuid);
  if (core_uuid.empty())
    memcpy(h.core_uuid, h.emit_uuid, 16);
  else
    ok = ParseHex16(core_uuid, h.core_uuid) && ok;
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
  if (!code || !code_end || !meta || !meta_end || meta_end - meta < 104)
    return refuse("symbols: no rt_aot_code..rt_aot_code_end and rt_aot_meta..rt_aot_meta_end");

  ImageHeader got, want;
  memcpy(&got, meta, sizeof(got));
  u8 want_bytes[sizeof(ImageHeader)];
  u8 self[16];
  AotHeader(want_bytes, got.nblocks, static_cast<u32>(code_end - code),
            SelfUuid(self) ? Hex16(self) : std::string());
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
  if (end - w < 2 + R_COUNT || w[1] != R_COUNT || w[0] > got.code_size)
    return refuse("routines: not this core's routine table");
  const u32 routines_size = w[0];
  const u32* entries = w + 2;
  for (int i = 0; i < R_COUNT; i++)
    if (entries[i] >= routines_size)
      return refuse(fmt::format("routines: entry {} at {:#x} is past their end", i, entries[i]));
  w = entries + R_COUNT;
  m_aot->image_blocks.clear();
  for (u32 i = 0; i < got.nblocks; i++)
  {
    if (end - w < 6)
      return refuse(fmt::format("blocks: the meta ends inside block {}", i));
    ImageBlock b{w[0], w[1], w[2], w[3], w[4], w[5], w + 6, w + 6 + 2 * static_cast<u64>(w[2])};
    if (static_cast<u64>(end - b.ops) < 2ULL * b.nops + 2ULL * b.nhooks ||
        static_cast<u64>(b.code_off) + b.code_len > got.code_size || b.code_off < routines_size)
      return refuse(fmt::format("blocks: block {} ({:08x}) is out of bounds", i, b.ea));
    m_aot->image_blocks.emplace(static_cast<u64>(b.feature_flags) << 32 | b.ea, b);
    w = b.hooks + 2 * b.nhooks;
  }
  m_aot->image_handle = handle;
  m_aot->image_code = code;
  m_aot->image_code_size = static_cast<size_t>(code_end - code);
  blocks.SetImageCode(code, code_end);
  AotBindRoutines(code, entries);
  return true;
}

// A block the dispatcher did not find: install the image's block for it when its ops are the
// analyzer's on live memory; otherwise load stops, and interp runs it on the Cached Interpreter.
void JitArm64::AotMiss(u32 em_address)
{
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
    JitBlock* b = blocks.AllocateBlock(em_address);
    b->normalEntry = const_cast<u8*>(m_aot->image_code + ib.code_off);
    b->near_begin = b->near_end = b->far_begin = b->far_end = nullptr;
    blocks.FinalizeBlock(*b, false, code_block, m_code_buffer);
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
  fprintf(m_aot->log, "B %08x %x %u %zu %016" PRIx64 " %u %zu", b.effectiveAddress,
          b.feature_flags, code_block.m_num_instructions, len, Fnv64(code, len),
          m_aot->imports.unresolved_in_unit, hooks.size() / 2);
  for (u32 i = 0; i < code_block.m_num_instructions; i++)
    fprintf(m_aot->log, " %08x:%08x", m_code_buffer[i].address, m_code_buffer[i].inst.hex);
  for (size_t i = 0; i < hooks.size(); i += 2)
    fprintf(m_aot->log, " %08x:%x", hooks[i], hooks[i + 1]);
  fputc('\n', m_aot->log);
  if (GetSettings().corrupt == b.effectiveAddress)
    AotDumpCode("shape", code, len);
}

void JitArm64::AotReport()
{
  const auto& s = m_aot->stats;
  fprintf(stderr,
          "JitArm64 AOT stats: %" PRIu64 " compiled (%" PRIu64 " with an unresolved host address), %" PRIu64
          " installed, %" PRIu64 " missed, %" PRIu64 " interpreted\n",
          s.compiled, s.unresolved_blocks, s.installs, s.misses, s.interp_blocks);
}

void JitArm64::AotShutdown()
{
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
  FILE* f = fopen(cfg.log.c_str(), "r");
  if (!f)
  {
    fprintf(stderr, "JitArm64 AOT emit: cannot read %s\n", cfg.log.c_str());
    std::exit(2);
  }
  struct Rec
  {
    u32 ea, ff, nops;
    size_t len;
    u64 hash;
    u32 unresolved, nhooks;
    std::vector<u32> ops, hooks;
  };
  std::vector<Rec> recs;
  std::map<std::tuple<u32, u32, std::vector<u32>, std::vector<u32>>, size_t> seen;
  u32 dup_differs = 0, routines_differ = 0;
  char tag[4];
  while (fscanf(f, "%3s", tag) == 1)
  {
    if (tag[0] == 'R')
    {
      size_t size, nimports;
      u64 hash, ihash, ahash;
      if (fscanf(f, "%zu %" SCNx64 " %zu %" SCNx64 " %" SCNx64, &size, &hash, &nimports, &ihash,
                 &ahash) != 5)
        break;
      if (size != m_aot->routines_size || hash != Fnv64(m_aot->routines_begin, size) ||
          nimports != m_aot->imports.names.size() || ihash != AotImportsHash() ||
          ahash != AotAbiHash())
      {
        fprintf(stderr, "JitArm64 AOT emit: the routines or imports differ from the shape run's\n");
        routines_differ++;
      }
      continue;
    }
    Rec r;
    if (fscanf(f, "%x %x %u %zu %" SCNx64 " %u %u", &r.ea, &r.ff, &r.nops, &r.len, &r.hash,
               &r.unresolved, &r.nhooks) != 7)
      break;
    r.ops.resize(2 * r.nops);
    for (u32 i = 0; i < r.nops; i++)
      if (fscanf(f, " %x:%x", &r.ops[2 * i], &r.ops[2 * i + 1]) != 2)
        break;
    r.hooks.resize(2 * r.nhooks);
    for (u32 i = 0; i < r.nhooks; i++)
      if (fscanf(f, " %x:%x", &r.hooks[2 * i], &r.hooks[2 * i + 1]) != 2)
        break;
    auto [it, fresh] = seen.emplace(std::make_tuple(r.ea, r.ff, r.ops, r.hooks), recs.size());
    if (!fresh)
    {
      if (recs[it->second].hash != r.hash || recs[it->second].len != r.len)
        dup_differs++;
      continue;
    }
    recs.push_back(std::move(r));
  }
  fclose(f);

  std::vector<u8> code(m_aot->routines_begin, m_aot->routines_begin + m_aot->routines_size);
  std::vector<u32> meta_blocks;
  u32 differs = 0, unresolved = 0, failed = 0;
  m_aot_emitting = true;
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
    Jit(r.ea, false);
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
             r.unresolved)
    {
      AotDumpCode("emit", bcode, len);
      if (m_aot->imports.unresolved_in_unit || r.unresolved)
        unresolved++;
      else
        differs++;
      fprintf(stderr, "JitArm64 AOT emit: %08x differs (%zu bytes against %zu)\n", r.ea, len,
              r.len);
    }
    const u32 off = static_cast<u32>(code.size());
    code.insert(code.end(), bcode, bcode + len);
    meta_blocks.insert(meta_blocks.end(),
                       {r.ea, r.ff, r.nops, r.nhooks, off, static_cast<u32>(len)});
    meta_blocks.insert(meta_blocks.end(), r.ops.begin(), r.ops.end());
    meta_blocks.insert(meta_blocks.end(), r.hooks.begin(), r.hooks.end());
  }
  m_ppc_state.feature_flags = static_cast<CPUEmuFeatureFlags>(saved_ff);

  std::vector<u8> meta(sizeof(ImageHeader));
  if (!AotHeader(meta.data(), static_cast<u32>(recs.size()), static_cast<u32>(code.size()),
                 cfg.core_uuid))
  {
    fprintf(stderr, "JitArm64 AOT emit: no LC_UUID, or DOLPHIN_AOT_CORE_UUID is not one\n");
    std::exit(2);
  }
  std::vector<u32> body = {static_cast<u32>(m_aot->routines_size), R_COUNT};
  for (int i = 0; i < R_COUNT; i++)
    body.push_back(static_cast<u32>(m_aot->routines[i] - m_aot->routines_begin));
  body.insert(body.end(), meta_blocks.begin(), meta_blocks.end());
  const u8* bb = reinterpret_cast<const u8*>(body.data());
  meta.insert(meta.end(), bb, bb + 4 * body.size());

  const std::string code_path = cfg.image + ".code", meta_path = cfg.image + ".meta";
  remove(code_path.c_str());
  remove(meta_path.c_str());
  const bool bad = differs || unresolved || failed || dup_differs || routines_differ;
  fprintf(stderr,
          "JitArm64 AOT emit: %zu blocks (%u duplicate records compiled differently), %zu bytes "
          "of code (routines %zu); %u differ from the shape run's, %u hold a host address, %u "
          "failed\n",
          recs.size(), dup_differs, code.size(), m_aot->routines_size, differs, unresolved, failed);
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
