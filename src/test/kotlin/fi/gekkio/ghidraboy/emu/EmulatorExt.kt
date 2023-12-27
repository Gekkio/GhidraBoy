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
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.fail

fun EmulatorHelper.step() {
    val success = step(TaskMonitor.DUMMY)
    if (!success) {
        fail<Unit>(lastError)
    }
}

fun EmulatorHelper.write(
    address: UShort,
    vararg bytes: UByte,
) = writeMemory(
    language.addressFactory.defaultAddressSpace.getAddress(address.toLong()),
    bytes.map { it.toByte() }.toByteArray(),
)

fun EmulatorHelper.read(address: UShort): UByte =
    readMemoryByte(
        language.addressFactory.defaultAddressSpace.getAddress(address.toLong()),
    ).toUByte()

fun EmulatorHelper.read(
    address: UShort,
    length: Int,
): UByteArray =
    readMemory(
        language.addressFactory.defaultAddressSpace.getAddress(address.toLong()),
        length,
    ).map { it.toUByte() }.toUByteArray()

fun EmulatorHelper.assertA(a: UByte) = assertEquals(a, readA())

fun EmulatorHelper.assertF(f: UByte) = assertEquals(f, readF())

fun EmulatorHelper.assertB(b: UByte) = assertEquals(b, readB())

fun EmulatorHelper.assertC(c: UByte) = assertEquals(c, readC())

fun EmulatorHelper.assertD(d: UByte) = assertEquals(d, readD())

fun EmulatorHelper.assertE(e: UByte) = assertEquals(e, readE())

fun EmulatorHelper.assertH(h: UByte) = assertEquals(h, readH())

fun EmulatorHelper.assertL(l: UByte) = assertEquals(l, readL())

fun EmulatorHelper.assertAF(af: UShort) = assertEquals(af, readAF())

fun EmulatorHelper.assertBC(bc: UShort) = assertEquals(bc, readBC())

fun EmulatorHelper.assertDE(de: UShort) = assertEquals(de, readDE())

fun EmulatorHelper.assertHL(hl: UShort) = assertEquals(hl, readHL())

fun EmulatorHelper.assertPC(pc: UShort) = assertEquals(pc, readPC())

fun EmulatorHelper.assertSP(sp: UShort) = assertEquals(sp, readSP())

fun EmulatorHelper.readA(): UByte = this.readRegister("A").toInt().toUByte()

fun EmulatorHelper.readF(): UByte = this.readRegister("F").toInt().toUByte()

fun EmulatorHelper.readB(): UByte = this.readRegister("B").toInt().toUByte()

fun EmulatorHelper.readC(): UByte = this.readRegister("C").toInt().toUByte()

fun EmulatorHelper.readD(): UByte = this.readRegister("D").toInt().toUByte()

fun EmulatorHelper.readE(): UByte = this.readRegister("E").toInt().toUByte()

fun EmulatorHelper.readH(): UByte = this.readRegister("H").toInt().toUByte()

fun EmulatorHelper.readL(): UByte = this.readRegister("L").toInt().toUByte()

fun EmulatorHelper.readAF(): UShort = this.readRegister("AF").toInt().toUShort()

fun EmulatorHelper.readBC(): UShort = this.readRegister("BC").toInt().toUShort()

fun EmulatorHelper.readDE(): UShort = this.readRegister("DE").toInt().toUShort()

fun EmulatorHelper.readHL(): UShort = this.readRegister("HL").toInt().toUShort()

fun EmulatorHelper.readPC(): UShort = this.readRegister("PC").toInt().toUShort()

fun EmulatorHelper.readSP(): UShort = this.readRegister("SP").toInt().toUShort()

fun EmulatorHelper.writeA(a: UByte) = this.writeRegister("A", a.toLong())

fun EmulatorHelper.writeF(f: UByte) = this.writeRegister("F", f.toLong())

fun EmulatorHelper.writeB(b: UByte) = this.writeRegister("B", b.toLong())

fun EmulatorHelper.writeC(c: UByte) = this.writeRegister("C", c.toLong())

fun EmulatorHelper.writeD(d: UByte) = this.writeRegister("D", d.toLong())

fun EmulatorHelper.writeE(e: UByte) = this.writeRegister("E", e.toLong())

fun EmulatorHelper.writeH(h: UByte) = this.writeRegister("H", h.toLong())

fun EmulatorHelper.writeL(l: UByte) = this.writeRegister("L", l.toLong())

fun EmulatorHelper.writeAF(af: UShort) = this.writeRegister("AF", af.toLong())

fun EmulatorHelper.writeBC(bc: UShort) = this.writeRegister("BC", bc.toLong())

fun EmulatorHelper.writeDE(de: UShort) = this.writeRegister("DE", de.toLong())

fun EmulatorHelper.writeHL(hl: UShort) = this.writeRegister("HL", hl.toLong())

fun EmulatorHelper.writePC(pc: UShort) = this.writeRegister("PC", pc.toLong())

fun EmulatorHelper.writeSP(sp: UShort) = this.writeRegister("SP", sp.toLong())
