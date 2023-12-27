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

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtensionContext
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.ArgumentsProvider
import org.junit.jupiter.params.provider.ArgumentsSource
import org.junit.jupiter.params.provider.EnumSource
import java.util.stream.Stream

class ControlFlowInstructionTest : EmuTest() {
    @Test
    fun `JP nn`() {
        emulator.write(0x0000u, 0xc3u, 0x34u, 0x12u)
        emulator.step()
        emulator.assertPC(0x1234u)
    }

    @Test
    fun `JP HL`() {
        emulator.writeHL(0x1234u)
        emulator.write(0x0000u, 0xe9u)
        emulator.step()
        emulator.assertPC(0x1234u)
    }

    @ParameterizedTest
    @ArgumentsSource(Conditions::class)
    fun `JP cc, nn`(
        cc: Condition,
        taken: Boolean,
    ) {
        emulator.writeF((if (taken) cc else cc.flip()).testFlags)
        emulator.write(0x000u, cc.jpOpcode, 0x34u, 0x12u)
        emulator.step()
        if (taken) {
            emulator.assertPC(0x1234u)
        } else {
            emulator.assertPC(0x0003u)
        }
    }

    @Test
    fun `JR e (positive)`() {
        emulator.write(0x0000u, 0x18u, 0x7fu)
        emulator.step()
        emulator.assertPC(0x0081u)
    }

    @Test
    fun `JR e (negative)`() {
        emulator.write(0x0000u, 0x18u, 0x80u)
        emulator.step()
        emulator.assertPC(0xff82u)
    }

    @ParameterizedTest
    @ArgumentsSource(Conditions::class)
    fun `JR cc, e (positive)`(
        cc: Condition,
        taken: Boolean,
    ) {
        emulator.writeF((if (taken) cc else cc.flip()).testFlags)
        emulator.write(0x000u, cc.jrOpcode, 0x7fu)
        emulator.step()
        if (taken) {
            emulator.assertPC(0x0081u)
        } else {
            emulator.assertPC(0x0002u)
        }
    }

    @ParameterizedTest
    @ArgumentsSource(Conditions::class)
    fun `JR cc, e (negative)`(
        cc: Condition,
        taken: Boolean,
    ) {
        emulator.writeF((if (taken) cc else cc.flip()).testFlags)
        emulator.write(0x000u, cc.jrOpcode, 0x80u)
        emulator.step()
        if (taken) {
            emulator.assertPC(0xff82u)
        } else {
            emulator.assertPC(0x0002u)
        }
    }

    @Test
    fun `CALL nn`() {
        emulator.writePC(0xabcdu)
        emulator.writeSP(0xbfffu)
        emulator.write(emulator.readSP(), 0x00u, 0x00u)
        emulator.write(0xabcdu, 0xcdu, 0x34u, 0x12u)
        emulator.step()
        emulator.assertPC(0x1234u)
        emulator.assertSP(0xbffdu)
        assertEquals((0xd0u).toUByte(), emulator.read(0xbffdu))
        assertEquals((0xabu).toUByte(), emulator.read(0xbffeu))
    }

    @ParameterizedTest
    @ArgumentsSource(Conditions::class)
    fun `CALL cc, nn`(
        cc: Condition,
        taken: Boolean,
    ) {
        emulator.writePC(0xabcdu)
        emulator.writeSP(0xbfffu)
        emulator.writeF((if (taken) cc else cc.flip()).testFlags)
        emulator.write(emulator.readSP(), 0x00u, 0x00u)
        emulator.write(0xabcdu, cc.callOpcode, 0x34u, 0x12u)
        emulator.step()
        if (taken) {
            emulator.assertPC(0x1234u)
            emulator.assertSP(0xbffdu)
            assertEquals((0xd0u).toUByte(), emulator.read(0xbffdu))
            assertEquals((0xabu).toUByte(), emulator.read(0xbffeu))
        } else {
            emulator.assertPC(0xabd0u)
            emulator.assertSP(0xbfffu)
        }
    }

    @Test
    fun `RET`() {
        emulator.writePC(0x1234u)
        emulator.writeSP(0xbffdu)
        emulator.write(emulator.readSP(), 0xcdu, 0xabu)
        emulator.write(0x1234u, 0xc9u)
        emulator.step()
        emulator.assertPC(0xabcdu)
        emulator.assertSP(0xbfffu)
    }

    @ParameterizedTest
    @ArgumentsSource(Conditions::class)
    fun `RET cc, nn`(
        cc: Condition,
        taken: Boolean,
    ) {
        emulator.writePC(0x1234u)
        emulator.writeSP(0xbffdu)
        emulator.writeF((if (taken) cc else cc.flip()).testFlags)
        emulator.write(emulator.readSP(), 0xcdu, 0xabu)
        emulator.write(0x1234u, cc.retOpcode)
        emulator.step()
        if (taken) {
            emulator.assertPC(0xabcdu)
            emulator.assertSP(0xbfffu)
        } else {
            emulator.assertPC(0x1235u)
            emulator.assertSP(0xbffdu)
        }
    }

    @Test
    fun `RETI`() {
        val ignore = IgnorePCode()
        emulator.registerCallOtherCallback("IME", ignore)
        emulator.writePC(0x1234u)
        emulator.writeSP(0xbffdu)
        emulator.write(emulator.readSP(), 0xcdu, 0xabu)
        emulator.write(0x1234u, 0xd9u)
        emulator.step()
        assertTrue(ignore.triggered)
        emulator.assertPC(0xabcdu)
        emulator.assertSP(0xbfffu)
    }

    @ParameterizedTest
    @EnumSource
    fun `RST`(rst: Rst) {
        emulator.writePC(0xabcdu)
        emulator.writeSP(0xbfffu)
        emulator.write(emulator.readSP(), 0x00u, 0x00u)
        emulator.write(0xabcdu, rst.opcode)
        emulator.step()
        emulator.assertPC(rst.target)
        emulator.assertSP(0xbffdu)
        assertEquals((0xceu).toUByte(), emulator.read(0xbffdu))
        assertEquals((0xabu).toUByte(), emulator.read(0xbffeu))
    }
}

private class Conditions : ArgumentsProvider {
    override fun provideArguments(context: ExtensionContext): Stream<out Arguments> =
        Condition.values().flatMap { listOf(Arguments.of(it, false), Arguments.of(it, true)) }.stream()
}

enum class Rst(val opcode: UByte, val target: UShort) {
    Rst00(0xc7u, 0x0000u),
    Rst08(0xcfu, 0x0008u),
    Rst10(0xd7u, 0x0010u),
    Rst18(0xdfu, 0x0018u),
    Rst20(0xe7u, 0x0020u),
    Rst28(0xefu, 0x0028u),
    Rst30(0xf7u, 0x0030u),
    Rst38(0xffu, 0x0038u),
}

enum class Condition(
    val testFlags: UByte,
    val jrOpcode: UByte,
    val jpOpcode: UByte,
    val callOpcode: UByte,
    val retOpcode: UByte,
) {
    NC(0b1110_0000u, 0x30u, 0xd2u, 0xd4u, 0xd0u),
    C(0b0001_0000u, 0x38u, 0xdau, 0xdcu, 0xd8u),
    NZ(0b0111_0000u, 0x20u, 0xc2u, 0xc4u, 0xc0u),
    Z(0b1000_0000u, 0x28u, 0xcau, 0xccu, 0xc8u),
    ;

    fun flip(): Condition =
        when (this) {
            NC -> C
            C -> NC
            NZ -> Z
            Z -> NZ
        }
}
