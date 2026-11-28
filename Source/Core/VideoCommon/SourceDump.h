// Copyright 2026 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

// An analysis-only companion of texture dumping (retro-trainer PLAN OPS-04): beside Dolphin's
// decoded tex1_ PNGs it writes what the game authored, into the same directory
// (File::GetUserPath(D_DUMPTEXTURES_IDX) + the game id):
//   <tex1 name without its TLUT part>.idx   a colour-indexed texture's indices, row-major, raw
//                                            width x height: one byte per texel for C4 and C8, a
//                                            little-endian u16 for C14X2;
//   tlut_<xxh64 of the whole TLUT>_<TLUTFormat>.bin  the TLUT as the game loaded it (big-endian
//                                            u16 entries; 16 for C4, 256 for C8, 16384 for C14X2);
//   textures.tsv                             a line per texture this process created: its tex1
//                                            name, width, height, TextureFormat, .idx name, TLUT
//                                            name, mip levels (- where none);
// and, when DOLPHIN_DUMP_TEXTURES_USAGE=<prefix> is set, per texture name the frames it was bound
// in and its binds (<prefix>.counts.tsv, rewritten every 600 frames and at shutdown), and every
// DOLPHIN_DUMP_TEXTURES_EVERY-th frame's bound names (<prefix>.frames.txt, default every 300).
// Every function is called only while g_ActiveConfig.bDumpTextures is set.

#pragma once

#include <string>

#include "Common/CommonTypes.h"

class TextureInfo;

namespace VideoCommon::SourceDump
{
// A texture entry was decoded from guest memory under tex1 name `name`, with `levels` levels.
void OnCreate(const TextureInfo& info, const std::string& name, u32 levels);
// A texture entry named `name` was bound for a draw.
void OnBind(const std::string& name);
void OnFrameEnd();
void Flush();
}  // namespace VideoCommon::SourceDump
