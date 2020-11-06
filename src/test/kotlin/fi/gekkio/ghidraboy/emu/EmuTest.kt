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
package fi.gekkio.ghidraboy.emu

import fi.gekkio.ghidraboy.IntegrationTest
import fi.gekkio.ghidraboy.withTransaction
import ghidra.app.emulator.EmulatorHelper
import ghidra.program.database.ProgramDB
import ghidra.program.model.listing.Program
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach

open class EmuTest : IntegrationTest() {
    protected lateinit var program: Program
    protected lateinit var emulator: EmulatorHelper

    @BeforeEach
    private fun beforeEach() {
        val consumer = object {}
        program = ProgramDB("test", language, language.defaultCompilerSpec, consumer)
        program.withTransaction {
            program.memory.createUninitializedBlock("rom", address(0x0000), 0x10000, false)
        }
        emulator = EmulatorHelper(program)
        emulator.memoryFaultHandler = FailOnMemoryFault(emulator)
    }

    @AfterEach
    private fun afterEach() {
        emulator.dispose()
    }
}
