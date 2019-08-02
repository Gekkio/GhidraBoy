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

import ghidra.app.util.MemoryBlockUtil;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

import java.io.ByteArrayInputStream;

public final class Ghidra90Compat {
    private Ghidra90Compat() {
    }

    public static MemoryBlock createUninitializedBlock(Program program, boolean isOverlay, String name, Address start, long length, String comment, String source, boolean r, boolean w, boolean x, MessageLog log) {
        var util = new MemoryBlockUtil(program, MemoryConflictHandler.NEVER_OVERWRITE);
        return util.createUninitializedBlock(isOverlay, name, start, length, comment, source, r, w, x);
    }

    public static MemoryBlock createInitializedBlock(Program program, boolean isOverlay, String name, Address start, byte[] rom, long offset, long length, String comment, String source, boolean r, boolean w, boolean x, MessageLog log) throws AddressOverflowException {
        var util = new MemoryBlockUtil(program, MemoryConflictHandler.NEVER_OVERWRITE);
        var dataInput = new ByteArrayInputStream(rom, (int) offset, (int) length);
        return util.createInitializedBlock(name, start, dataInput, length, comment, source, r, w, x, TaskMonitor.DUMMY);
    }
}
