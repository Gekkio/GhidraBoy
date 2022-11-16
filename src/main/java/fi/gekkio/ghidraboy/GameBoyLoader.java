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

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static fi.gekkio.ghidraboy.BootRomUtils.detectBootRom;
import static fi.gekkio.ghidraboy.GameBoyUtils.addHardwareBlocks;
import static fi.gekkio.ghidraboy.GameBoyUtils.populateHardwareBlocks;
import static fi.gekkio.ghidraboy.RomUtils.detectRom;
import static ghidra.app.util.MemoryBlockUtils.createInitializedBlock;
import static ghidra.app.util.MemoryBlockUtils.createUninitializedBlock;
import static ghidra.program.model.data.DataUtilities.createData;

public class GameBoyLoader extends AbstractProgramLoader {
    private static final String OPT_HW_BLOCKS = "Create GB hardware memory blocks";
    private static final String OPT_DATA_TYPES = "Create GB data types";
    private static final String OPT_KIND = "Hardware type";

    @Override
    public String getName() {
        return "Game Boy";
    }

    @Override
    public LoaderTier getTier() {
        return LoaderTier.SPECIALIZED_TARGET_LOADER;
    }

    @Override
    public int getTierPriority() {
        return 0;
    }

    @Override
    public boolean supportsLoadIntoProgram() {
        return true;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        var result = new ArrayList<LoadSpec>();
        if (detectBootRom(provider).isPresent() || detectRom(provider).isPresent()) {
            result.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("SM83:LE:16:default", "default"), true));
        }
        return result;
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject, boolean isLoadIntoProgram) {
        var result = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
        result.add(new Option(OPT_HW_BLOCKS, true));
        result.add(new Option(OPT_DATA_TYPES, true));
        try {
            var bootRom = detectBootRom(provider);
            if (bootRom.isPresent()) {
                result.add(new GameBoyKindOption(OPT_KIND, bootRom.get()));
                return result;
            }
            var rom = detectRom(provider);
            if (rom.isPresent()) {
                result.add(new GameBoyKindOption(OPT_KIND, rom.get()));
                return result;
            }
        } catch (IOException ignored) {
        }
        result.add(new GameBoyKindOption(OPT_KIND, GameBoyKind.GB));
        return result;
    }

    @Override
    protected List<LoadedProgram> loadProgram(ByteProvider provider, String programName, DomainFolder programFolder, LoadSpec loadSpec, List<Option> options, MessageLog log, Object consumer, TaskMonitor monitor) throws IOException, CancelledException {
        var result = new ArrayList<LoadedProgram>();
        var pair = loadSpec.getLanguageCompilerSpec();
        var language = getLanguageService().getLanguage(pair.languageID);
        var compiler = language.getCompilerSpecByID(pair.compilerSpecID);

        var baseAddress = language.getAddressFactory().getDefaultAddressSpace().getAddress(0);
        var program = createProgram(provider, programName, baseAddress, getName(), language, compiler, consumer);
        var success = false;
        try {
            var kind = OptionUtils.getOption(OPT_KIND, options, GameBoyKind.GB);
            if (OptionUtils.getBooleanOptionValue(OPT_DATA_TYPES, options, true)) {
                int id = program.startTransaction("Create GB data types");
                try {
                    DataTypes.addAll(program.getDataTypeManager());
                } finally {
                    program.endTransaction(id, true);
                }
            }
            if (loadInto(provider, loadSpec, options, log, program, monitor)) {
                createDefaultMemoryBlocks(program, language, log);

                if (OptionUtils.getBooleanOptionValue(OPT_HW_BLOCKS, options, true)) {
                    int id = program.startTransaction("Create GB hardware memory blocks");
                    try {
                        addHardwareBlocks(program, kind, log);
                        populateHardwareBlocks(program, kind);
                    } catch (InvalidInputException | CodeUnitInsertionException e) {
                        log.appendException(e);
                    } finally {
                        program.endTransaction(id, true);
                    }
                }
                success = result.add(new LoadedProgram(program, programFolder));
            }
        } finally {
            if (!success) {
                program.release(consumer);
            }
        }
        return result;
    }

    @Override
    protected boolean loadProgramInto(ByteProvider provider, LoadSpec loadSpec, List<Option> options, MessageLog log, Program program, TaskMonitor monitor) throws IOException, CancelledException {
        var as = program.getAddressFactory().getDefaultAddressSpace();

        var bootRom = detectBootRom(provider);
        var rom = MemoryBlockUtils.createFileBytes(program, provider, monitor);

        if (bootRom.isPresent()) {
            var cgb = GameBoyKind.CGB.equals(bootRom.get());
            try {
                createInitializedBlock(program, false, cgb ? "boot0" : "boot", as.getAddress(0x0000), rom, 0, 0x100, "", getName(), false, false, true, log);
                createUninitializedBlock(program, false, "rom", as.getAddress(0x0100), 0x50, "", getName(), true, false, false, log);
                if (cgb) {
                    createInitializedBlock(program, false, "boot1", as.getAddress(0x0200), rom, 0x200, 0x700, "", getName(), false, false, true, log);
                }
                var st = program.getSymbolTable();
                st.addExternalEntryPoint(as.getAddress(0x0000));
                st.createLabel(as.getAddress(0x0000), "boot_entry", SourceType.IMPORTED);
            } catch (AddressOverflowException | InvalidInputException e) {
                log.appendException(e);
                throw new CancelledException("Loading failed: " + e.getMessage());
            }
        } else {
            var banked = provider.length() > 0x8000;
            try {
                createInitializedBlock(program, false, banked ? "rom0" : "rom", as.getAddress(0x0000), rom, 0, banked ? 0x4000 : 0x8000, "Cartridge ROM (offset 0)", getName(), true, false, true, log);
                if (banked) {
                    var romX = as.getAddress(0x4000);
                    var offset = 0x4000;
                    var bank = 1;
                    while (offset < rom.getSize()) {
                        createInitializedBlock(program, true, "rom" + bank, romX, rom, offset, 0x4000, "Cartridge ROM (offset %d)".formatted(offset), getName(), true, false, true, log);
                        offset += 0x4000;
                        bank += 1;
                    }
                }
                createUninitializedBlock(program, false, "xram", as.getAddress(0xa000), 0x2000, "Cartridge RAM", getName(), true, true, true, log);

                var st = program.getSymbolTable();
                st.createLabel(as.getAddress(0x0000), "rst00", SourceType.IMPORTED);
                st.createLabel(as.getAddress(0x0008), "rst08", SourceType.IMPORTED);
                st.createLabel(as.getAddress(0x0010), "rst10", SourceType.IMPORTED);
                st.createLabel(as.getAddress(0x0018), "rst18", SourceType.IMPORTED);
                st.createLabel(as.getAddress(0x0020), "rst20", SourceType.IMPORTED);
                st.createLabel(as.getAddress(0x0028), "rst28", SourceType.IMPORTED);
                st.createLabel(as.getAddress(0x0030), "rst30", SourceType.IMPORTED);
                st.createLabel(as.getAddress(0x0038), "rst38", SourceType.IMPORTED);
                st.createLabel(as.getAddress(0x0040), "intr_vblank", SourceType.IMPORTED);
                st.createLabel(as.getAddress(0x0048), "intr_stat", SourceType.IMPORTED);
                st.createLabel(as.getAddress(0x0050), "intr_timer", SourceType.IMPORTED);
                st.createLabel(as.getAddress(0x0058), "intr_serial", SourceType.IMPORTED);
                st.createLabel(as.getAddress(0x0060), "intr_joypad", SourceType.IMPORTED);
                st.addExternalEntryPoint(as.getAddress(0x0100));
                try {
                    var entry = program.getFunctionManager().createFunction("entry", as.getAddress(0x0100), new AddressSet(as.getAddress(0x0100), as.getAddress(0x103)), SourceType.IMPORTED);
                    entry.setNoReturn(true);
                } catch (OverlappingFunctionException e) {
                    log.appendException(e);
                }
            } catch (AddressOverflowException | InvalidInputException e) {
                log.appendException(e);
                throw new CancelledException("Loading failed: " + e.getMessage());
            }
        }
        var createDataTypes = OptionUtils.getBooleanOptionValue(OPT_DATA_TYPES, options, true);

        if (createDataTypes || program.getDataTypeManager().contains(DataTypes.LOGO)) {
            try {
                createData(program, as.getAddress(0x0104), DataTypes.LOGO, -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
            } catch (CodeUnitInsertionException e) {
                log.appendException(e);
            }
        }
        if (createDataTypes || program.getDataTypeManager().contains(DataTypes.HEADER)) {
            try {
                createData(program, as.getAddress(0x0134), DataTypes.HEADER, -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
            } catch (CodeUnitInsertionException e) {
                log.appendException(e);
            }
        }
        return true;
    }
}
