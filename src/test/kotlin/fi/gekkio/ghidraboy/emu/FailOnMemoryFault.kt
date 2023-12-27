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

import ghidra.app.emulator.EmulatorHelper
import ghidra.pcode.emulate.EmulateExecutionState
import ghidra.pcode.memstate.MemoryFaultHandler
import ghidra.program.model.address.Address
import org.junit.jupiter.api.Assertions

class FailOnMemoryFault(private val emulator: EmulatorHelper) : MemoryFaultHandler {
    override fun uninitializedRead(
        address: Address,
        size: Int,
        buf: ByteArray,
        bufOffset: Int,
    ): Boolean {
        if (emulator.emulateExecutionState == EmulateExecutionState.INSTRUCTION_DECODE) {
            return false
        }
        val pc = emulator.executionAddress
        emulator.program.getRegister(address, size)?.let {
            Assertions.fail<Unit>("Uninitialized register read at $pc: $it")
        }
        Assertions.fail<Unit>("Uninitialized memory read at $pc: ${address.toString(true)}:$size")
        return true
    }

    override fun unknownAddress(
        address: Address,
        write: Boolean,
    ): Boolean {
        val pc = emulator.executionAddress
        if (write) {
            Assertions.fail<Unit>("Unknown address written at $pc: $address")
        } else {
            Assertions.fail<Unit>("Unknown address read at $pc: $address")
        }
        return false
    }
}
