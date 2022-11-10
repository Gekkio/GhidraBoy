// Copyright 2019-2020 Joonas Javanainen <joonas.javanainen@gmail.com>
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
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.InvalidInputException;

import static fi.gekkio.ghidraboy.DataTypes.array;
import static fi.gekkio.ghidraboy.DataTypes.u8;
import static ghidra.app.util.MemoryBlockUtils.createUninitializedBlock;
import static ghidra.program.model.data.DataUtilities.createData;

public final class GameBoyUtils {
    private GameBoyUtils() {
    }

    public static void addHardwareBlocks(Program program, GameBoyKind kind, MessageLog log) {
        var source = kind == GameBoyKind.CGB ? "Game Boy Color hardware" : "Game Boy hardware";
        var as = program.getAddressFactory().getDefaultAddressSpace();
        if (kind == GameBoyKind.CGB) {
            createUninitializedBlock(program, true, "vram0", as.getAddress(0x8000), 0x2000, "Video RAM (bank 0)", source, true, true, false, log);
            createUninitializedBlock(program, true, "vram1", as.getAddress(0x8000), 0x2000, "Video RAM (bank 1)", source, true, true, false, log);
        } else {
            createUninitializedBlock(program, false, "vram", as.getAddress(0x8000), 0x2000, "Video RAM", source, true, true, false, log);
        }
        if (kind == GameBoyKind.CGB) {
            createUninitializedBlock(program, false, "wram0", as.getAddress(0xc000), 0x1000, "Work RAM (bank 0)", source, true, true, true, log);
            for (int i = 1; i <= 7; i++) {
                createUninitializedBlock(program, true, "wram" + i, as.getAddress(0xd000), 0x1000, "Work RAM (bank %d)".formatted(i), source, true, true, true, log);
            }
        } else {
            createUninitializedBlock(program, false, "wram", as.getAddress(0xc000), 0x2000, "Work RAM", source, true, true, true, log);
        }
        createUninitializedBlock(program, false, "oam", as.getAddress(0xfe00), 0xa0, "Object Attribute Memory RAM", source, true, true, false, log);
        var io = createUninitializedBlock(program, false, "io", as.getAddress(0xff00), 0x80, "I/O registers", source, true, true, false, log);
        if (io != null) {
            io.setVolatile(true);
        }
        createUninitializedBlock(program, false, "hram", as.getAddress(0xff80), 0x7f, "High RAM", source, true, true, true, log);
        var ie = createUninitializedBlock(program, false, "ie", as.getAddress(0xffff), 0x1, "Interrupt Enable register", source, true, true, false, log);
        if (ie != null) {
            ie.setVolatile(true);
        }
    }

    public static void populateHardwareBlocks(Program program, GameBoyKind kind) throws CodeUnitInsertionException, InvalidInputException {
        var as = program.getAddressFactory().getDefaultAddressSpace();
        addHwData(program, "P1", as.getAddress(0xff00), u8);
        addHwData(program, "SB", as.getAddress(0xff01), u8);
        addHwData(program, "SC", as.getAddress(0xff02), u8);
        addHwData(program, "DIV", as.getAddress(0xff04), u8);
        addHwData(program, "TIMA", as.getAddress(0xff05), u8);
        addHwData(program, "TMA", as.getAddress(0xff06), u8);
        addHwData(program, "TAC", as.getAddress(0xff07), u8);
        addHwData(program, "IF", as.getAddress(0xff0f), u8);
        addHwData(program, "NR10", as.getAddress(0xff10), u8);
        addHwData(program, "NR11", as.getAddress(0xff11), u8);
        addHwData(program, "NR12", as.getAddress(0xff12), u8);
        addHwData(program, "NR13", as.getAddress(0xff13), u8);
        addHwData(program, "NR14", as.getAddress(0xff14), u8);
        addHwData(program, "NR21", as.getAddress(0xff16), u8);
        addHwData(program, "NR22", as.getAddress(0xff17), u8);
        addHwData(program, "NR23", as.getAddress(0xff18), u8);
        addHwData(program, "NR24", as.getAddress(0xff19), u8);
        addHwData(program, "NR30", as.getAddress(0xff1a), u8);
        addHwData(program, "NR31", as.getAddress(0xff1b), u8);
        addHwData(program, "NR32", as.getAddress(0xff1c), u8);
        addHwData(program, "NR33", as.getAddress(0xff1d), u8);
        addHwData(program, "NR34", as.getAddress(0xff1e), u8);
        addHwData(program, "NR41", as.getAddress(0xff20), u8);
        addHwData(program, "NR42", as.getAddress(0xff21), u8);
        addHwData(program, "NR43", as.getAddress(0xff22), u8);
        addHwData(program, "NR44", as.getAddress(0xff23), u8);
        addHwData(program, "NR50", as.getAddress(0xff24), u8);
        addHwData(program, "NR51", as.getAddress(0xff25), u8);
        addHwData(program, "NR52", as.getAddress(0xff26), u8);
        addHwData(program, "WAVE", as.getAddress(0xff30), array(u8, 16));
        addHwData(program, "LCDC", as.getAddress(0xff40), u8);
        addHwData(program, "STAT", as.getAddress(0xff41), u8);
        addHwData(program, "SCY", as.getAddress(0xff42), u8);
        addHwData(program, "SCX", as.getAddress(0xff43), u8);
        addHwData(program, "LY", as.getAddress(0xff44), u8);
        addHwData(program, "LYC", as.getAddress(0xff45), u8);
        addHwData(program, "DMA", as.getAddress(0xff46), u8);
        addHwData(program, "BGP", as.getAddress(0xff47), u8);
        addHwData(program, "OBP0", as.getAddress(0xff48), u8);
        addHwData(program, "OBP1", as.getAddress(0xff49), u8);
        addHwData(program, "WY", as.getAddress(0xff4a), u8);
        addHwData(program, "WX", as.getAddress(0xff4b), u8);
        if (kind == GameBoyKind.CGB) {
            addHwData(program, "KEY1", as.getAddress(0xff4d), u8);
            addHwData(program, "VBK", as.getAddress(0xff4f), u8);
        }
        addHwData(program, "BOOT", as.getAddress(0xff50), u8);
        if (kind == GameBoyKind.CGB) {
            addHwData(program, "HDMA1", as.getAddress(0xff51), u8);
            addHwData(program, "HDMA2", as.getAddress(0xff52), u8);
            addHwData(program, "HDMA3", as.getAddress(0xff53), u8);
            addHwData(program, "HDMA4", as.getAddress(0xff54), u8);
            addHwData(program, "HDMA5", as.getAddress(0xff55), u8);
            addHwData(program, "RP", as.getAddress(0xff56), u8);
            addHwData(program, "BCPS", as.getAddress(0xff68), u8);
            addHwData(program, "BCPD", as.getAddress(0xff69), u8);
            addHwData(program, "OCPS", as.getAddress(0xff6a), u8);
            addHwData(program, "OCPD", as.getAddress(0xff6b), u8);
            addHwData(program, "SVBK", as.getAddress(0xff70), u8);
            addHwData(program, "PCM12", as.getAddress(0xff76), u8);
            addHwData(program, "PCM34", as.getAddress(0xff77), u8);
        }
        addHwData(program, "IE", as.getAddress(0xffff), u8);
    }

    private static void addHwData(Program program, String name, Address address, DataType dataType) throws CodeUnitInsertionException, InvalidInputException {
        createData(program, address, dataType, -1, false, DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
        program.getSymbolTable().createLabel(address, name, SourceType.IMPORTED).setPinned(true);
    }

}
