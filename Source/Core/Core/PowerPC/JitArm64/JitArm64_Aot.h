// Copyright 2026 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

// JitArm64's AOT form (retro-trainer PLAN-handheld HH-34): a game's blocks compiled on the Mac into
// code that holds no host address, so a dylib of them runs where nothing may be written and then
// executed. retro-trainer's cores/README.md, "AOT images", says how an image is made and shipped;
// JitArm64_Aot.cpp's header comment is the format's home.
//
// The modes (JitArm64Aot::Configure; DolphinLibretro/Boot.cpp reads them from the environment, or
// the core option rt_aot_image):
// - shape: the JIT, emitting AOT-shaped code (below) from its usual MAP_JIT cache, logging each
//   block it compiles: its key, the guest words its compile read, its code's length and hash;
// - emit: re-compiles each logged block from its logged words into plain memory, checks each is
//   byte for byte the code the shape run compiled, writes <image>.code and <image>.meta, and exits;
// - load: maps no code cache; the shared routines and the blocks come from the image's dylib, a
//   block installed where the JIT would have compiled it once its words are checked; a miss stops;
// - interp: load, with a miss run by the Cached Interpreter, charged as the JIT charges.
//
// AOT-shaped code: every host address through PowerPCState::aot_imports (Arm64Gen's
// AotImportResolver: pointers, calls, branches to the routines); no far code (it is emitted inline
// and branched over); no block linking, BLR optimization, fastmem, speculative constants, paired
// quantize assumption, gather pipe or constant-address specializations, so a block's code is a
// function of its words and its feature flags alone.

#pragma once

#include <array>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

#include "Common/Arm64Emitter.h"
#include "Common/CommonTypes.h"

namespace JitArm64Aot
{
enum class Mode
{
  Off,
  Shape,
  Emit,
  Load,
  Interp,
};

struct Settings
{
  Mode mode = Mode::Off;
  std::string image;      // emit: the prefix it writes; load, interp: the dylib
  std::string log;        // shape: the block log it writes; emit: the one it reads
  std::string core_uuid;  // emit: the LC_UUID of the core build that will load the image
  u32 corrupt = 0;        // emit: this block's code gets one instruction changed (a red receipt)
};

// "shape", "emit", "load", "interp"; false for anything else.
bool ParseMode(const char* text, Mode* mode);
void Configure(const Settings& settings);
const Settings& GetSettings();
inline bool Active()
{
  return GetSettings().mode != Mode::Off;
}
// What the last load or interp init did with its image, for the frontend: admitted, or why not.
const std::string& LastOutcome();

// The routine entry points an image carries, in order (offsets from the image's code start).
enum Routine : u32
{
  R_ENTER_CODE,
  R_DISPATCHER,
  R_DISPATCHER_NO_TIMING_CHECK,
  R_DISPATCHER_NO_CHECK,
  R_DO_TIMING,
  R_DISPATCHER_EXIT,
  R_FRES,
  R_FRSQRTE,
  R_CDTS,
  R_CSTD,
  R_FPRF_SINGLE,
  R_FPRF_DOUBLE,
  R_FMADDS_EFT,
  R_PS_MADD_EFT,
  R_QUANTIZED,  // 4 tables of 8: paired load, single load, paired store, single store
  R_COUNT = R_QUANTIZED + 32,
};

class Imports final : public Arm64Gen::AotImportResolver
{
public:
  int Slot(const void* target) const override;
  void Unresolved(const void* target, const char* what) override;
  // The slot for `value`, named; a value already held keeps its first slot.
  int Add(const std::string& name, const void* value);
  void Set(int slot, const void* value);

  std::vector<std::string> names;
  std::vector<const void*> values;
  std::unordered_map<const void*, int> slot_of;
  u32 unresolved_in_unit = 0;
  std::unordered_map<const void*, std::string> unresolved_seen;
};

struct ImageBlock
{
  u32 ea, feature_flags, nops, nhooks, code_off, code_len;
  const u32* ops;    // 2 * nops words: each op's address and instruction
  const u32* hooks;  // 2 * nhooks words: an op's address and its HLE hook index, where it has one
};

struct State
{
  Mode mode = Mode::Off;
  Imports imports;
  std::array<std::array<const u8*, 8>, 4> quantized{};
  std::array<const u8*, R_COUNT> routines{};
  FILE* log = nullptr;
  const u8* routines_begin = nullptr;
  size_t routines_size = 0;
  // load, interp
  void* image_handle = nullptr;
  const u8* image_code = nullptr;
  size_t image_code_size = 0;
  std::unordered_multimap<u64, ImageBlock> image_blocks;  // (feature_flags << 32 | ea)
  struct
  {
    u64 compiled = 0, unresolved_blocks = 0, installs = 0, misses = 0, interp_blocks = 0;
  } stats;
};

u64 Fnv64(const void* data, size_t size, u64 h = 0xcbf29ce484222325ULL);
// Writable and executable regions, executable ones, and executable ones no file backs, of this
// process, printed with `label` (macOS; elsewhere a line saying it cannot count).
void VMReport(const char* label);
}  // namespace JitArm64Aot
