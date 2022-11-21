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

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class MiscInstructionTest : EmuTest() {
    @Test
    fun `NOP`() {
        emulator.write(0x0000u, 0x00u)
        emulator.step()
        emulator.assertPC(0x0001u)
    }

    @Test
    fun `DI`() {
        val ignore = IgnorePCode()
        emulator.registerCallOtherCallback("IME", ignore)
        emulator.write(0x0000u, 0xf3u)
        emulator.step()
        assertTrue(ignore.triggered)
        emulator.assertPC(0x0001u)
    }

    @Test
    fun `EI`() {
        val ignore = IgnorePCode()
        emulator.registerCallOtherCallback("IME", ignore)
        emulator.write(0x0000u, 0xfbu)
        emulator.step()
        assertTrue(ignore.triggered)
        emulator.assertPC(0x0001u)
    }

    @Test
    fun `HALT`() {
        val ignore = IgnorePCode()
        emulator.registerCallOtherCallback("halt", ignore)
        emulator.write(0x0000u, 0x76u)
        emulator.step()
        assertTrue(ignore.triggered)
        emulator.assertPC(0x0001u)
    }

    @Test
    fun `STOP`() {
        val ignore = IgnorePCode()
        emulator.registerCallOtherCallback("stop", ignore)
        emulator.write(0x0000u, 0x10u)
        emulator.step()
        assertTrue(ignore.triggered)
        emulator.assertPC(0x0001u)
    }

    @Test
    fun `DAA`() {
        emulator.registerCallOtherCallback("daaOperand", IgnorePCode())
        emulator.writeF(0b0000_0000u)
        emulator.writeA(0x00u)
        emulator.write(0x0000u, 0x27u)
        emulator.step()
        emulator.assertPC(0x0001u)
    }

    @Test
    fun `CCF when C=1`() {
        emulator.writeF(0b1111_0000u)
        emulator.write(0x0000u, 0x3fu)
        emulator.step()
        emulator.assertPC(0x0001u)
        emulator.assertF(0b1000_0000u)
    }

    @Test
    fun `CCF when C=0`() {
        emulator.writeF(0b1110_0000u)
        emulator.write(0x0000u, 0x3fu)
        emulator.step()
        emulator.assertPC(0x0001u)
        emulator.assertF(0b1001_0000u)
    }

    @Test
    fun `SCF`() {
        emulator.writeF(0b1110_0000u)
        emulator.write(0x0000u, 0x37u)
        emulator.step()
        emulator.assertPC(0x0001u)
        emulator.assertF(0b1001_0000u)
    }

    @Test
    fun `CPL`() {
        emulator.writeF(0b1001_0000u)
        emulator.writeA(0x55u)
        emulator.write(0x0000u, 0x2fu)
        emulator.step()
        emulator.assertPC(0x0001u)
        emulator.assertF(0b1111_0000u)
        emulator.assertA(0xaau)
    }
}
