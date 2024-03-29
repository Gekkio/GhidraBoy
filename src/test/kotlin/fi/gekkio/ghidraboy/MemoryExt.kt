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
package fi.gekkio.ghidraboy

import ghidra.program.model.address.Address
import ghidra.program.model.mem.Memory
import ghidra.program.model.mem.MemoryBlock
import ghidra.util.task.TaskMonitor

fun Memory.loadBytes(
    name: String,
    start: Address,
    bytes: ByteArray,
    overlay: Boolean = false,
): MemoryBlock = createInitializedBlock(name, start, bytes.inputStream(), bytes.size.toLong(), TaskMonitor.DUMMY, overlay)
