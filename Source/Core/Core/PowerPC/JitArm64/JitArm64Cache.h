// Copyright 2008 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <vector>

#include "Common/Arm64Emitter.h"
#include "Core/PowerPC/JitCommon/JitCache.h"

class JitBase;

typedef void (*CompiledCode)();

class JitArm64BlockCache : public JitBaseBlockCache
{
public:
  explicit JitArm64BlockCache(JitBase& jit);

  void Init() override;

  void DestroyBlock(JitBlock& block) override;

  const std::vector<std::pair<u8*, u8*>>& GetRangesToFreeNear() const;
  const std::vector<std::pair<u8*, u8*>>& GetRangesToFreeFar() const;

  void ClearRangesToFree();

  // JitArm64's AOT load: blocks whose code is in [begin, end) are the image's, never written.
  void SetImageCode(const u8* begin, const u8* end)
  {
    m_image_begin = begin;
    m_image_end = end;
  }

  void WriteLinkBlock(Arm64Gen::ARM64XEmitter& emit, const JitBlock::LinkData& source,
                      const JitBlock* dest = nullptr);

  static constexpr size_t BLOCK_LINK_SIZE = 3 * sizeof(u32);
  static constexpr size_t BLOCK_LINK_FAST_BL_OFFSET = BLOCK_LINK_SIZE - sizeof(u32);

private:
  void WriteLinkBlock(const JitBlock::LinkData& source, const JitBlock* dest) override;
  void WriteDestroyBlock(const JitBlock& block) override;

  const u8* m_image_begin = nullptr;
  const u8* m_image_end = nullptr;
  std::vector<std::pair<u8*, u8*>> m_ranges_to_free_on_next_codegen_near;
  std::vector<std::pair<u8*, u8*>> m_ranges_to_free_on_next_codegen_far;
};
