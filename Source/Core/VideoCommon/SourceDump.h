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
// A texture read from memory an EFB or XFB copy wrote in the last 60 frames is the game's own
// rendering, not its art: it is neither dumped nor counted (snp2 decodes two or three 608x456 copies a frame).
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
// An EFB or XFB copy wrote [address, address + size) of guest memory.
void OnEfbCopy(u32 address, u32 size);
// A texture entry was decoded from guest memory under tex1 name `name`, with `levels` levels.
// False when it lies in memory a copy wrote lately (OnEfbCopy): then nothing of it is dumped.
bool OnCreate(const TextureInfo& info, const std::string& name, u32 levels);
// A texture entry named `name` was bound for a draw.
void OnBind(const std::string& name);
void OnFrameEnd();
void Flush();
}  // namespace VideoCommon::SourceDump
