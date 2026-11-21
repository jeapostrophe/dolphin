// Copyright 2026 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

namespace PPCAnalyst
{
struct CodeOp;
}

// The Cached Interpreter's JIT-timed mode (CachedInterpreter::SetJitTiming; JitArm64's AOT interp,
// retro-trainer HH-34): what a JIT makes of a block's ops, asked of the JIT itself, from the
// predicates its own compile asks, so the interpreter charges each block as the JIT's AOT form
// charges it. That form keeps the gather pipe optimization off (MMU::SetAotForm), whose batched
// flushes and mid-block exception checks nothing here models: both write the pipe through MMIO.
class JitTiming
{
public:
  enum class Exit
  {
    Plain,
    Exceptions,          // every pending exception is taken first (WriteExceptionExit)
    ExternalExceptions,  // the external ones only
  };

  // How the JIT leaves a block after `op`, which can end it.
  virtual Exit ExitAfter(const PPCAnalyst::CodeOp& op) const = 0;
  // Whether the JIT runs ops[0], ops[1] and ops[2] (a dcbx, an addi and a bdnz) as one batched
  // loop; `can_merge` is CanMergeNextInstructions(2) where ops[0] stands.
  virtual bool BatchesDcbxLoop(const PPCAnalyst::CodeOp* ops, bool can_merge) const = 0;
  // Whether the JIT skips ops[1] (a dcbst of the line the dcbt ops[0] names); `can_merge` is
  // CanMergeNextInstructions(1) where ops[0] stands.
  virtual bool SkipsNextOp(const PPCAnalyst::CodeOp* ops, bool can_merge) const = 0;

protected:
  ~JitTiming() = default;
};
