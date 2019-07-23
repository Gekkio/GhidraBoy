// Copyright 2019 Joonas Javanainen <joonas.javanainen@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package fi.gekkio.ghidraboy;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;

import static ghidra.app.util.MemoryBlockUtils.createUninitializedBlock;

public final class GameBoyUtils {
    private GameBoyUtils() {
    }

    public static void addHardwareBlocks(Program program, GameBoyKind kind, MessageLog log) {
        var source = kind == GameBoyKind.CGB ? "Game Boy Color hardware" : "Game Boy hardware";
        var as = program.getAddressFactory().getDefaultAddressSpace();
        if (kind == GameBoyKind.CGB) {
            createUninitializedBlock(program, true, "vram0", as.getAddress(0x8000), 0x2000, "", source, true, true, false, log);
            createUninitializedBlock(program, true, "vram1", as.getAddress(0x8000), 0x2000, "", source, true, true, false, log);
        } else {
            createUninitializedBlock(program, false, "vram", as.getAddress(0x8000), 0x2000, "", source, true, true, false, log);
        }
        createUninitializedBlock(program, false, "xram", as.getAddress(0xa000), 0x2000, "", source, true, true, true, log);
        if (kind == GameBoyKind.CGB) {
            createUninitializedBlock(program, false, "wram0", as.getAddress(0xc000), 0x1000, "", source, true, true, true, log);
            for (int i = 1; i <= 7; i++) {
                createUninitializedBlock(program, true, "wram" + i, as.getAddress(0xd000), 0x1000, "", source, true, true, true, log);
            }
        } else {
            createUninitializedBlock(program, false, "wram", as.getAddress(0xc000), 0x2000, "", source, true, true, true, log);
        }
        createUninitializedBlock(program, false, "oam", as.getAddress(0xfe00), 0xa0, "", source, true, true, false, log);
        var io = createUninitializedBlock(program, false, "io", as.getAddress(0xff00), 0x80, "", source, true, true, false, log);
        if (io != null) {
            io.setVolatile(true);
        }
        createUninitializedBlock(program, false, "hram", as.getAddress(0xff80), 0x7f, "", source, true, true, true, log);
        createUninitializedBlock(program, false, "ie", as.getAddress(0xffff), 0x1, "", source, true, true, false, log);
    }
}
