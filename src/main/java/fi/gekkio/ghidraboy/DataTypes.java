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

import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;

import java.util.Arrays;

public final class DataTypes {
    private DataTypes() {
    }

    public static final ByteDataType u8 = ByteDataType.dataType;
    public static final WordDataType u16 = WordDataType.dataType;
    public static final CharDataType ch = CharDataType.dataType;

    public static final TypeDef LOGO;
    public static final Enum CGB_FLAG;
    public static final Structure TITLE_BLOCK_OLD;
    public static final Structure TITLE_BLOCK_NEW;
    public static final Union TITLE_BLOCK;
    public static final Enum SGB_FLAG;
    public static final Enum CART_TYPE;
    public static final Enum ROM_SIZE;
    public static final Enum RAM_SIZE;
    public static final Enum REGION;
    public static final Structure HEADER;

    static {
        LOGO = new TypedefDataType("logo", array(u8, 0x30));

        CGB_FLAG = new EnumDataType("cgb_flag", 1);
        CGB_FLAG.add("NONE", 0x00);
        CGB_FLAG.add("SUPPORT", 0x80);
        CGB_FLAG.add("ONLY", 0xc0);

        TITLE_BLOCK_OLD = new StructureDataType("title_block_old", 0);
        TITLE_BLOCK_OLD.add(array(ch, 15), "title", null);
        TITLE_BLOCK_OLD.add(CGB_FLAG, "cgb_flag", null);

        TITLE_BLOCK_NEW = new StructureDataType("title_block_new", 0);
        TITLE_BLOCK_NEW.add(array(ch, 11), "title", null);
        TITLE_BLOCK_NEW.add(array(ch, 4), "manufacturer_code", null);
        TITLE_BLOCK_NEW.add(CGB_FLAG, "cgb_flag", null);

        TITLE_BLOCK = new UnionDataType("title_block");
        TITLE_BLOCK.add(array(ch, 16), "title_only", null);
        TITLE_BLOCK.add(TITLE_BLOCK_OLD, "old_format", null);
        TITLE_BLOCK.add(TITLE_BLOCK_NEW, "new_format", null);

        SGB_FLAG = new EnumDataType("sflag", 1);
        SGB_FLAG.add("NONE", 0x00);
        SGB_FLAG.add("SUPPORT", 0x03);

        CART_TYPE = new EnumDataType("cart_type", 1);
        CART_TYPE.add("ROM_ONLY", 0x00);
        CART_TYPE.add("MBC1", 0x01);
        CART_TYPE.add("MBC1_RAM", 0x02);
        CART_TYPE.add("MBC1_RAM_BATT", 0x03);
        CART_TYPE.add("MBC2", 0x05);
        CART_TYPE.add("MBC2_BATT", 0x06);
        CART_TYPE.add("RAM", 0x08);
        CART_TYPE.add("RAM_BATT", 0x09);
        CART_TYPE.add("MMM01", 0x0b);
        CART_TYPE.add("MMM01_RAM", 0x0c);
        CART_TYPE.add("MMM01_RAM_BATT", 0x0d);
        CART_TYPE.add("MBC3_RTC_BATT", 0x0f);
        CART_TYPE.add("MBC3_RAM_RTC_BATT", 0x10);
        CART_TYPE.add("MBC3", 0x11);
        CART_TYPE.add("MBC3_RAM", 0x12);
        CART_TYPE.add("MBC3_RAM_BATT", 0x13);
        CART_TYPE.add("MBC5", 0x19);
        CART_TYPE.add("MBC5_RAM", 0x1a);
        CART_TYPE.add("MBC5_RAM_BATT", 0x1b);
        CART_TYPE.add("MBC5_RUMBLE", 0x1c);
        CART_TYPE.add("MBC5_RAM_RUMBLE", 0x1d);
        CART_TYPE.add("MBC5_RAM_BATT_RUMBLE", 0x1e);
        CART_TYPE.add("MBC6", 0x20);
        CART_TYPE.add("MBC7", 0x22);
        CART_TYPE.add("POCKET_CAMERA", 0xfc);
        CART_TYPE.add("TAMA5", 0xfd);
        CART_TYPE.add("HUC3", 0xfe);
        CART_TYPE.add("HUC1", 0xff);

        ROM_SIZE = new EnumDataType("rom_size", 1);
        ROM_SIZE.add("32K", 0x00);
        ROM_SIZE.add("64K", 0x01);
        ROM_SIZE.add("128K", 0x02);
        ROM_SIZE.add("256K", 0x03);
        ROM_SIZE.add("512K", 0x04);
        ROM_SIZE.add("1MB", 0x05);
        ROM_SIZE.add("2MB", 0x06);
        ROM_SIZE.add("4MB", 0x07);
        ROM_SIZE.add("8MB", 0x08);

        RAM_SIZE = new EnumDataType("ram_size", 1);
        RAM_SIZE.add("NONE", 0x00);
        RAM_SIZE.add("2KB", 0x01);
        RAM_SIZE.add("8KB", 0x02);
        RAM_SIZE.add("32KB", 0x03);
        RAM_SIZE.add("128KB", 0x04);
        RAM_SIZE.add("64KB", 0x05);

        REGION = new EnumDataType("region", 1);
        REGION.add("JAPAN", 0x00);
        REGION.add("WORLD", 0x01);

        HEADER = new StructureDataType("header", 0);
        HEADER.add(TITLE_BLOCK, "title_block", null);
        HEADER.add(array(ch, 2), "new_licensee_code", null);
        HEADER.add(SGB_FLAG, "sgb_flag", null);
        HEADER.add(CART_TYPE, "cartridge_type", null);
        HEADER.add(ROM_SIZE, "rom_size", null);
        HEADER.add(RAM_SIZE, "ram_size", null);
        HEADER.add(REGION, "region", null);
        HEADER.add(u8, "old_licensee_code", null);
        HEADER.add(u8, "mask_rom_version", null);
        HEADER.add(u8, "header_checksum", null);
        HEADER.add(u16, "global_checksum", null);
    }

    public static void addAll(DataTypeManager m) {
        DataType types[] = {LOGO, CGB_FLAG, TITLE_BLOCK_OLD, TITLE_BLOCK_NEW, TITLE_BLOCK, SGB_FLAG, CART_TYPE, ROM_SIZE, RAM_SIZE, REGION, HEADER};
        Category c = m.createCategory(new CategoryPath(CategoryPath.ROOT, "Game Boy"));
        Arrays.stream(types).forEach(d -> c.addDataType(d, DataTypeConflictHandler.DEFAULT_HANDLER));
    }

    static Array array(DataType d, int size) {
        return new ArrayDataType(d, size, -1);
    }
}
