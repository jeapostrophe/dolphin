// Copyright 2014 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstddef>

#include "Common/CommonTypes.h"
#include "Common/RangeSizeSet.h"
#include "Core/PowerPC/CachedInterpreter/CachedInterpreterBlockCache.h"
#include "Core/PowerPC/CachedInterpreter/CachedInterpreterEmitter.h"
#include "Core/PowerPC/JitCommon/JitBase.h"
#include "Core/PowerPC/PPCAnalyst.h"

namespace CoreTiming
{
class CoreTimingManager;
}
namespace CPU
{
enum class State;
}
class Interpreter;

class CachedInterpreter : public JitBase, public CachedInterpreterCodeBlock
{
public:
  explicit CachedInterpreter(Core::System& system);
  CachedInterpreter(const CachedInterpreter&) = delete;
  CachedInterpreter(CachedInterpreter&&) = delete;
  CachedInterpreter& operator=(const CachedInterpreter&) = delete;
  CachedInterpreter& operator=(CachedInterpreter&&) = delete;
  ~CachedInterpreter() override;

  void Init() override;
  void Shutdown() override;

  bool HandleFault(uintptr_t access_address, SContext* ctx) override { return false; }
  void ClearCache() override;

  void Run() override;
  void SingleStep() override;

  void Jit(u32 address) override;
  void Jit(u32 address, bool clear_cache_and_retry_on_failure);
  bool DoJit(u32 address, JitBlock* b, u32 nextPC);

  void EraseSingleBlock(const JitBlock& block) override;
  std::vector<MemoryStats> GetMemoryStats() const override;

  static std::size_t Disassemble(const JitBlock& block, std::ostream& stream);

  std::size_t DisassembleNearCode(const JitBlock& block, std::ostream& stream) const override;
  std::size_t DisassembleFarCode(const JitBlock& block, std::ostream& stream) const override;

  JitBaseBlockCache* GetBlockCache() override { return &m_block_cache; }
  const char* GetName() const override { return "Cached Interpreter"; }
  const CommonAsmRoutinesBase* GetAsmRoutines() override { return nullptr; }

  // JitArm64's AOT interp runs the blocks its image lacks here, charged as JitArm64 charges them
  // (retro-trainer HH-34): blocks formed with the JIT's analyzer options, and a block that goes on
  // past a branch (a followed one, or a conditional one not taken) ends only where JitArm64's
  // would, when the branch goes elsewhere than the next word. Set before Init.
  // `jit_op` says what JitArm64 makes of an op: how it leaves a block after one that can end
  // it (JIT_EXIT_MASK: a plain exit, one that first takes every pending exception, or external
  // ones only), and whether it is its dcbx, which runs a dcbx/addi/bdnz loop's iterations at once.
  enum JitOp : u32
  {
    JIT_EXIT_PLAIN,
    JIT_EXIT_EXCEPTIONS,
    JIT_EXIT_EXTERNAL_EXCEPTIONS,
    JIT_EXIT_MASK = 3,
    JIT_OP_DCBX = 4,
  };
  void SetJitTimed(bool jit_timed, u32 (*jit_op)(const PPCAnalyst::CodeOp& op))
  {
    m_jit_timed = jit_timed;
    m_aot_form = jit_timed;  // and flag merging, as there, never depends on stepping
    m_jit_op = jit_op;
  }
  bool AotHasBlock() { return m_block_cache.Dispatch() != nullptr; }
  // One block, from the cache or compiled now, at the PC (what Run does between timing checks).
  void AotExecuteOneBlock()
  {
    if (!m_block_cache.Dispatch())
      Jit(m_ppc_state.pc);
    ExecuteOneBlock();
  }

private:
  void ExecuteOneBlock();

  bool HandleFunctionHooking(u32 address);
  void WriteEndBlock();

  // Finds a free memory region and sets the code emitter to point at that region.
  // Returns false if no free memory region can be found.
  bool SetEmitterStateToFreeCodeRegion();

  void FreeRanges();
  void ResetFreeMemoryRanges();

  void LogGeneratedCode() const;

  struct StartProfiledBlockOperands;
  template <bool profiled>
  struct EndBlockOperands;
  struct InterpretOperands;
  struct InterpretAndCheckExceptionsOperands;
  struct HLEFunctionOperands;
  struct WriteBrokenBlockNPCOperands;
  struct CheckHaltOperands;
  struct CheckIdleOperands;
  struct EndBlockIfBranchedOperands;
  struct EndBlockCheckExceptionsOperands;
  struct DcbxLoopOperands;

  static s32 StartProfiledBlock(PowerPC::PowerPCState& ppc_state,
                                const StartProfiledBlockOperands& operands);
  static s32 StartProfiledBlock(std::ostream& stream, const StartProfiledBlockOperands& operands);
  template <bool profiled>
  static s32 EndBlock(PowerPC::PowerPCState& ppc_state, const EndBlockOperands<profiled>& operands);
  template <bool profiled>
  static s32 EndBlock(std::ostream& stream, const EndBlockOperands<profiled>& operands);
  template <bool write_pc>
  static s32 Interpret(PowerPC::PowerPCState& ppc_state, const InterpretOperands& operands);
  template <bool write_pc>
  static s32 Interpret(std::ostream& stream, const InterpretOperands& operands);
  template <bool write_pc>
  static s32 InterpretAndCheckExceptions(PowerPC::PowerPCState& ppc_state,
                                         const InterpretAndCheckExceptionsOperands& operands);
  template <bool write_pc>
  static s32 InterpretAndCheckExceptions(std::ostream& stream,
                                         const InterpretAndCheckExceptionsOperands& operands);
  static s32 HLEFunction(PowerPC::PowerPCState& ppc_state, const HLEFunctionOperands& operands);
  static s32 HLEFunction(std::ostream& stream, const HLEFunctionOperands& operands);
  static s32 WriteBrokenBlockNPC(PowerPC::PowerPCState& ppc_state,
                                 const WriteBrokenBlockNPCOperands& operands);
  static s32 WriteBrokenBlockNPC(std::ostream& stream, const WriteBrokenBlockNPCOperands& operands);
  static s32 CheckFPU(PowerPC::PowerPCState& ppc_state, const CheckHaltOperands& operands);
  static s32 CheckFPU(std::ostream& stream, const CheckHaltOperands& operands);
  static s32 CheckBreakpoint(PowerPC::PowerPCState& ppc_state, const CheckHaltOperands& operands);
  static s32 CheckBreakpoint(std::ostream& stream, const CheckHaltOperands& operands);
  static s32 CheckIdle(PowerPC::PowerPCState& ppc_state, const CheckIdleOperands& operands);
  static s32 CheckIdle(std::ostream& stream, const CheckIdleOperands& operands);
  static s32 EndBlockIfBranched(PowerPC::PowerPCState& ppc_state,
                                const EndBlockIfBranchedOperands& operands);
  static s32 EndBlockIfBranched(std::ostream& stream, const EndBlockIfBranchedOperands& operands);

  template <bool external>
  static s32 EndBlockCheckExceptions(PowerPC::PowerPCState& ppc_state,
                                     const EndBlockCheckExceptionsOperands& operands);
  template <bool external>
  static s32 EndBlockCheckExceptions(std::ostream& stream,
                                     const EndBlockCheckExceptionsOperands& operands);

  static s32 DcbxLoop(PowerPC::PowerPCState& ppc_state, const DcbxLoopOperands& operands);
  static s32 DcbxLoop(std::ostream& stream, const DcbxLoopOperands& operands);

  bool m_jit_timed = false;
  u32 (*m_jit_op)(const PPCAnalyst::CodeOp& op) = nullptr;

  Common::RangeSizeSet<u8*> m_free_ranges;
  CachedInterpreterBlockCache m_block_cache;
};

struct CachedInterpreter::StartProfiledBlockOperands
{
  JitBlock::ProfileData* profile_data;
};

template <>
struct CachedInterpreter::EndBlockOperands<false>
{
  u32 downcount;
  u32 num_load_stores;
  u32 num_fp_inst;
  u32 : 32;
};

template <>
struct CachedInterpreter::EndBlockOperands<true> : CachedInterpreter::EndBlockOperands<false>
{
  JitBlock::ProfileData* profile_data;
};

struct CachedInterpreter::InterpretOperands
{
  Interpreter& interpreter;
  void (*func)(Interpreter&, UGeckoInstruction);  // Interpreter::Instruction
  u32 current_pc;
  UGeckoInstruction inst;
};

struct CachedInterpreter::InterpretAndCheckExceptionsOperands : InterpretOperands
{
  PowerPC::PowerPCManager& power_pc;
  u32 downcount;
};

struct CachedInterpreter::HLEFunctionOperands
{
  Core::System& system;
  u32 current_pc;
  u32 hook_index;
};

struct CachedInterpreter::WriteBrokenBlockNPCOperands
{
  u32 current_pc;
  u32 : 32;
};

struct CachedInterpreter::CheckHaltOperands
{
  PowerPC::PowerPCManager& power_pc;
  u32 current_pc;
  u32 downcount;
};

struct CachedInterpreter::EndBlockIfBranchedOperands : CachedInterpreter::EndBlockOperands<false>
{
  u32 next_pc;
  u32 : 32;
};

struct CachedInterpreter::EndBlockCheckExceptionsOperands
    : CachedInterpreter::EndBlockOperands<false>
{
  PowerPC::PowerPCManager& power_pc;
  u32 next_pc;  // 0: none (the block's last op), else the op the block goes on to unbranched
  u32 : 32;
};

struct CachedInterpreter::DcbxLoopOperands : CachedInterpreter::InterpretOperands
{
  u32 rb;
  u32 cycles_per_loop;
};

struct CachedInterpreter::CheckIdleOperands
{
  CoreTiming::CoreTimingManager& core_timing;
  u32 idle_pc;
};
