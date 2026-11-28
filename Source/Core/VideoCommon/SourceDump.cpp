// Copyright 2026 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "VideoCommon/SourceDump.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <vector>

#include <fmt/format.h>
#include <xxhash.h>

#include "Common/FileUtil.h"
#include "Common/IOFile.h"
#include "Core/ConfigManager.h"
#include "VideoCommon/TextureDecoder.h"
#include "VideoCommon/TextureInfo.h"

namespace VideoCommon::SourceDump
{
namespace
{
struct Use
{
  u64 frames = 0;
  u64 binds = 0;
};

std::string s_usage_prefix;
u32 s_every = 300;
bool s_env_read = false;
u64 s_frame = 0;
std::map<std::string, Use> s_uses;
std::set<std::string> s_frame_names;
std::set<std::pair<u32, u32>> s_copies;  // [begin, end) of guest memory an EFB copy wrote

void ReadEnv()
{
  if (s_env_read)
    return;
  s_env_read = true;
  if (const char* p = getenv("DOLPHIN_DUMP_TEXTURES_USAGE"); p && *p)
    s_usage_prefix = p;
  if (const char* e = getenv("DOLPHIN_DUMP_TEXTURES_EVERY"); e && *e)
    s_every = std::max(1, atoi(e));
}

std::string DumpDir()
{
  return File::GetUserPath(D_DUMPTEXTURES_IDX) + SConfig::GetInstance().GetGameID() + "/";
}

void WriteFile(const std::string& path, const void* data, size_t size)
{
  if (File::Exists(path))
    return;
  File::IOFile f(path + ".part", "wb");
  if (f.WriteBytes(data, size) && f.Close())
    File::Rename(path + ".part", path);
}

// An IA8 TLUT whose entry k decodes to R = G = B = k & 0xff and A = k >> 8, so decoding a
// colour-indexed texture through it gives back its indices in linear order (TexDecoder_Decode
// does the GX block detiling).
const std::vector<u8>& IdentityTlut()
{
  static const std::vector<u8> tlut = [] {
    std::vector<u8> t(16384 * 2);
    for (u32 k = 0; k < 16384; ++k)
    {
      t[2 * k] = static_cast<u8>(k >> 8);
      t[2 * k + 1] = static_cast<u8>(k & 0xff);
    }
    return t;
  }();
  return tlut;
}
}  // namespace

void OnEfbCopy(u32 address, u32 size)
{
  s_copies.emplace(address, address + size);
}

bool OnCreate(const TextureInfo& info, const std::string& name, u32 levels)
{
  ReadEnv();
  const u32 begin = info.GetRawAddress(), end = begin + info.GetTextureSize();
  for (const auto& [b, e] : s_copies)
  {
    if (begin < e && b < end)
      return false;
  }
  const std::string dir = DumpDir();
  if (!File::IsDirectory(dir))
    File::CreateFullPath(dir);

  const TextureFormat format = info.GetTextureFormat();
  std::string idx_name = "-";
  std::string tlut_name = "-";
  if (IsColorIndexed(format) && info.GetPaletteSize())
  {
    const auto details = info.CalculateTextureName();
    idx_name = fmt::format("{}_{}_{}.idx", details.base_name, details.texture_name,
                           details.format_name);
    const u32 w = info.GetRawWidth(), h = info.GetRawHeight();
    const u32 ew = info.GetExpandedWidth(), eh = info.GetExpandedHeight();
    std::vector<u32> rgba(size_t(ew) * eh);
    TexDecoder_Decode(reinterpret_cast<u8*>(rgba.data()), info.GetData(), ew, eh, format,
                      IdentityTlut().data(), TLUTFormat::IA8);
    const bool wide = format == TextureFormat::C14X2;
    std::vector<u8> idx(size_t(w) * h * (wide ? 2 : 1));
    for (u32 y = 0; y < h; ++y)
    {
      for (u32 x = 0; x < w; ++x)
      {
        const u32 px = rgba[size_t(y) * ew + x];
        const u32 k = (px & 0xff) | ((px >> 24) << 8);
        const size_t i = size_t(y) * w + x;
        if (wide)
        {
          idx[2 * i] = static_cast<u8>(k & 0xff);
          idx[2 * i + 1] = static_cast<u8>(k >> 8);
        }
        else
        {
          idx[i] = static_cast<u8>(k);
        }
      }
    }
    WriteFile(dir + idx_name, idx.data(), idx.size());

    const u32 tlut_size = *info.GetPaletteSize();
    const u64 tlut_hash = XXH64(info.GetTlutAddress(), tlut_size, 0);
    tlut_name = fmt::format("tlut_{:016x}_{}.bin", tlut_hash, static_cast<int>(info.GetTlutFormat()));
    WriteFile(dir + tlut_name, info.GetTlutAddress(), tlut_size);
  }

  File::IOFile tsv(dir + "textures.tsv", "ab");
  const std::string line =
      fmt::format("{}\t{}\t{}\t{}\t{}\t{}\t{}\n", name, info.GetRawWidth(), info.GetRawHeight(),
                  static_cast<int>(format), idx_name, tlut_name, levels);
  tsv.WriteString(line);
  return true;
}

void OnBind(const std::string& name)
{
  ReadEnv();
  if (s_usage_prefix.empty() || name.empty())
    return;
  s_uses[name].binds++;
  s_frame_names.insert(name);
}

void OnFrameEnd()
{
  ReadEnv();
  if (s_usage_prefix.empty())
    return;
  for (const auto& n : s_frame_names)
    s_uses[n].frames++;
  if (s_frame % s_every == 0)
  {
    File::IOFile f(s_usage_prefix + ".frames.txt", "ab");
    std::string line = fmt::format("{}", s_frame);
    for (const auto& n : s_frame_names)
      line += " " + n;
    f.WriteString(line + "\n");
  }
  s_frame_names.clear();
  ++s_frame;
  if (s_frame % 600 == 0)
    Flush();
}

void Flush()
{
  if (s_usage_prefix.empty())
    return;
  std::string out = fmt::format("# frames {}\nname\tframes\tbinds\n", s_frame);
  for (const auto& [n, u] : s_uses)
    out += fmt::format("{}\t{}\t{}\n", n, u.frames, u.binds);
  File::WriteStringToFile(s_usage_prefix + ".counts.tsv.part", out);
  File::Rename(s_usage_prefix + ".counts.tsv.part", s_usage_prefix + ".counts.tsv");
}
}  // namespace VideoCommon::SourceDump
