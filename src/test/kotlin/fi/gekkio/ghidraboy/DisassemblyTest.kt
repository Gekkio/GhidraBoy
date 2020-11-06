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

import ghidra.app.emulator.EmulatorHelper
import ghidra.program.database.ProgramDB
import ghidra.program.disassemble.Disassembler
import ghidra.program.model.listing.CodeUnit
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class DisassemblyTest : IntegrationTest() {
    @Test
    fun `can disassemble NOP`() = test(0x00, "NOP")

    @Test
    fun `can disassemble LD BC, nn`() = test(0x01, "LD BC,0x1234", 0x34, 0x12)

    @Test
    fun `can disassemble LD (BC), A`() = test(0x02, "LD (BC),A")

    @Test
    fun `can disassemble INC BC`() = test(0x03, "INC BC")

    @Test
    fun `can disassemble INC B`() = test(0x04, "INC B")

    @Test
    fun `can disassemble DEC B`() = test(0x05, "DEC B")

    @Test
    fun `can disassemble LD B, n`() = test(0x06, "LD B,0x55", 0x55)

    @Test
    fun `can disassemble RLCA`() = test(0x07, "RLCA")

    @Test
    fun `can disassemble LD (nn), SP`() = test(0x08, "LD (0x1234),SP", 0x34, 0x12)

    @Test
    fun `can disassemble ADD HL, BC`() = test(0x09, "ADD HL,BC")

    @Test
    fun `can disassemble LD A, (BC)`() = test(0x0a, "LD A,(BC)")

    @Test
    fun `can disassemble DEC BC`() = test(0x0b, "DEC BC")

    @Test
    fun `can disassemble INC C`() = test(0x0c, "INC C")

    @Test
    fun `can disassemble DEC C`() = test(0x0d, "DEC C")

    @Test
    fun `can disassemble LD C, n`() = test(0x0e, "LD C,0x55", 0x55)

    @Test
    fun `can disassemble RRCA`() = test(0x0f, "RRCA")

    @Test
    fun `can disassemble STOP`() = test(0x10, "STOP")

    @Test
    fun `can disassemble LD DE, nn`() = test(0x11, "LD DE,0x1234", 0x34, 0x12)

    @Test
    fun `can disassemble LD (DE), A`() = test(0x12, "LD (DE),A")

    @Test
    fun `can disassemble INC DE`() = test(0x13, "INC DE")

    @Test
    fun `can disassemble INC D`() = test(0x14, "INC D")

    @Test
    fun `can disassemble DEC D`() = test(0x15, "DEC D")

    @Test
    fun `can disassemble LD D, n`() = test(0x16, "LD D,0x55", 0x55)

    @Test
    fun `can disassemble RLA`() = test(0x17, "RLA")

    @Test
    fun `can disassemble JR e (positive operand)`() = test(0x18, "JR 0x0057", 0x55)

    @Test
    fun `can disassemble JR e (negative operand)`() = test(0x18, "JR 0xffd7", 0xd5)

    @Test
    fun `can disassemble ADD HL, DE`() = test(0x19, "ADD HL,DE")

    @Test
    fun `can disassemble LD A, (DE)`() = test(0x1a, "LD A,(DE)")

    @Test
    fun `can disassemble DEC DE`() = test(0x1b, "DEC DE")

    @Test
    fun `can disassemble INC E`() = test(0x1c, "INC E")

    @Test
    fun `can disassemble DEC E`() = test(0x1d, "DEC E")

    @Test
    fun `can disassemble LD E, n`() = test(0x1e, "LD E,0x55", 0x55)

    @Test
    fun `can disassemble RRA`() = test(0x1f, "RRA")

    @Test
    fun `can disassemble JR NZ, e (positive operand)`() = test(0x20, "JR NZ,0x0057", 0x55)

    @Test
    fun `can disassemble JR NZ, e (negative operand)`() = test(0x20, "JR NZ,0xffd7", 0xd5)

    @Test
    fun `can disassemble LD HL, nn`() = test(0x21, "LD HL,0x1234", 0x34, 0x12)

    @Test
    fun `can disassemble LD (HL+), A`() = test(0x22, "LD (HL+),A")

    @Test
    fun `can disassemble INC HL`() = test(0x23, "INC HL")

    @Test
    fun `can disassemble INC H`() = test(0x24, "INC H")

    @Test
    fun `can disassemble DEC H`() = test(0x25, "DEC H")

    @Test
    fun `can disassemble LD H, n`() = test(0x26, "LD H,0x55", 0x55)

    @Test
    fun `can disassemble DAA`() = test(0x27, "DAA")

    @Test
    fun `can disassemble JR Z, e (positive operand)`() = test(0x28, "JR Z,0x0057", 0x55)

    @Test
    fun `can disassemble JR Z, e (negative operand)`() = test(0x28, "JR Z,0xffd7", 0xd5)

    @Test
    fun `can disassemble ADD HL, HL`() = test(0x29, "ADD HL,HL")

    @Test
    fun `can disassemble LD A, (HL+)`() = test(0x2a, "LD A,(HL+)")

    @Test
    fun `can disassemble DEC HL`() = test(0x2b, "DEC HL")

    @Test
    fun `can disassemble INC L`() = test(0x2c, "INC L")

    @Test
    fun `can disassemble DEC L`() = test(0x2d, "DEC L")

    @Test
    fun `can disassemble LD L, n`() = test(0x2e, "LD L,0x55", 0x55)

    @Test
    fun `can disassemble CPL`() = test(0x2f, "CPL")

    @Test
    fun `can disassemble JR NC, e (positive operand)`() = test(0x30, "JR NC,0x0057", 0x55)

    @Test
    fun `can disassemble JR NC, e (negative operand)`() = test(0x30, "JR NC,0xffd7", 0xd5)

    @Test
    fun `can disassemble LD SP, nn`() = test(0x31, "LD SP,0x1234", 0x34, 0x12)

    @Test
    fun `can disassemble LD (HL-), A`() = test(0x32, "LD (HL-),A")

    @Test
    fun `can disassemble INC SP`() = test(0x33, "INC SP")

    @Test
    fun `can disassemble INC (HL)`() = test(0x34, "INC (HL)")

    @Test
    fun `can disassemble DEC (HL)`() = test(0x35, "DEC (HL)")

    @Test
    fun `can disassemble LD (HL), n`() = test(0x36, "LD (HL),0x55", 0x55)

    @Test
    fun `can disassemble SCF`() = test(0x37, "SCF")

    @Test
    fun `can disassemble JR C, e (positive operand)`() = test(0x38, "JR C,0x0057", 0x55)

    @Test
    fun `can disassemble JR C, e (negative operand)`() = test(0x38, "JR C,0xffd7", 0xd5)

    @Test
    fun `can disassemble ADD HL, SP`() = test(0x39, "ADD HL,SP")

    @Test
    fun `can disassemble LD A, (HL-)`() = test(0x3a, "LD A,(HL-)")

    @Test
    fun `can disassemble DEC SP`() = test(0x3b, "DEC SP")

    @Test
    fun `can disassemble INC A`() = test(0x3c, "INC A")

    @Test
    fun `can disassemble DEC A`() = test(0x3d, "DEC A")

    @Test
    fun `can disassemble LD A, n`() = test(0x3e, "LD A,0x55", 0x55)

    @Test
    fun `can disassemble CCF`() = test(0x3f, "CCF")

    @Test
    fun `can disassemble LD B, B`() = test(0x40, "LD B,B")

    @Test
    fun `can disassemble LD B, C`() = test(0x41, "LD B,C")

    @Test
    fun `can disassemble LD B, D`() = test(0x42, "LD B,D")

    @Test
    fun `can disassemble LD B, E`() = test(0x43, "LD B,E")

    @Test
    fun `can disassemble LD B, H`() = test(0x44, "LD B,H")

    @Test
    fun `can disassemble LD B, L`() = test(0x45, "LD B,L")

    @Test
    fun `can disassemble LD B, (HL)`() = test(0x46, "LD B,(HL)")

    @Test
    fun `can disassemble LD B, A`() = test(0x47, "LD B,A")

    @Test
    fun `can disassemble LD C, B`() = test(0x48, "LD C,B")

    @Test
    fun `can disassemble LD C, C`() = test(0x49, "LD C,C")

    @Test
    fun `can disassemble LD C, D`() = test(0x4a, "LD C,D")

    @Test
    fun `can disassemble LD C, E`() = test(0x4b, "LD C,E")

    @Test
    fun `can disassemble LD C, H`() = test(0x4c, "LD C,H")

    @Test
    fun `can disassemble LD C, L`() = test(0x4d, "LD C,L")

    @Test
    fun `can disassemble LD C, (HL)`() = test(0x4e, "LD C,(HL)")

    @Test
    fun `can disassemble LD C, A`() = test(0x4f, "LD C,A")

    @Test
    fun `can disassemble LD D, B`() = test(0x50, "LD D,B")

    @Test
    fun `can disassemble LD D, C`() = test(0x51, "LD D,C")

    @Test
    fun `can disassemble LD D, D`() = test(0x52, "LD D,D")

    @Test
    fun `can disassemble LD D, E`() = test(0x53, "LD D,E")

    @Test
    fun `can disassemble LD D, H`() = test(0x54, "LD D,H")

    @Test
    fun `can disassemble LD D, L`() = test(0x55, "LD D,L")

    @Test
    fun `can disassemble LD D, (HL)`() = test(0x56, "LD D,(HL)")

    @Test
    fun `can disassemble LD D, A`() = test(0x57, "LD D,A")

    @Test
    fun `can disassemble LD E, B`() = test(0x58, "LD E,B")

    @Test
    fun `can disassemble LD E, C`() = test(0x59, "LD E,C")

    @Test
    fun `can disassemble LD E, D`() = test(0x5a, "LD E,D")

    @Test
    fun `can disassemble LD E, E`() = test(0x5b, "LD E,E")

    @Test
    fun `can disassemble LD E, H`() = test(0x5c, "LD E,H")

    @Test
    fun `can disassemble LD E, L`() = test(0x5d, "LD E,L")

    @Test
    fun `can disassemble LD E, (HL)`() = test(0x5e, "LD E,(HL)")

    @Test
    fun `can disassemble LD E, A`() = test(0x5f, "LD E,A")

    @Test
    fun `can disassemble LD H, B`() = test(0x60, "LD H,B")

    @Test
    fun `can disassemble LD H, C`() = test(0x61, "LD H,C")

    @Test
    fun `can disassemble LD H, D`() = test(0x62, "LD H,D")

    @Test
    fun `can disassemble LD H, E`() = test(0x63, "LD H,E")

    @Test
    fun `can disassemble LD H, H`() = test(0x64, "LD H,H")

    @Test
    fun `can disassemble LD H, L`() = test(0x65, "LD H,L")

    @Test
    fun `can disassemble LD H, (HL)`() = test(0x66, "LD H,(HL)")

    @Test
    fun `can disassemble LD H, A`() = test(0x67, "LD H,A")

    @Test
    fun `can disassemble LD L, B`() = test(0x68, "LD L,B")

    @Test
    fun `can disassemble LD L, C`() = test(0x69, "LD L,C")

    @Test
    fun `can disassemble LD L, D`() = test(0x6a, "LD L,D")

    @Test
    fun `can disassemble LD L, E`() = test(0x6b, "LD L,E")

    @Test
    fun `can disassemble LD L, H`() = test(0x6c, "LD L,H")

    @Test
    fun `can disassemble LD L, L`() = test(0x6d, "LD L,L")

    @Test
    fun `can disassemble LD L, (HL)`() = test(0x6e, "LD L,(HL)")

    @Test
    fun `can disassemble LD L, A`() = test(0x6f, "LD L,A")

    @Test
    fun `can disassemble LD (HL), B`() = test(0x70, "LD (HL),B")

    @Test
    fun `can disassemble LD (HL), C`() = test(0x71, "LD (HL),C")

    @Test
    fun `can disassemble LD (HL), D`() = test(0x72, "LD (HL),D")

    @Test
    fun `can disassemble LD (HL), E`() = test(0x73, "LD (HL),E")

    @Test
    fun `can disassemble LD (HL), H`() = test(0x74, "LD (HL),H")

    @Test
    fun `can disassemble LD (HL), L`() = test(0x75, "LD (HL),L")

    @Test
    fun `can disassemble HALT`() = test(0x76, "HALT")

    @Test
    fun `can disassemble LD (HL), A`() = test(0x77, "LD (HL),A")

    @Test
    fun `can disassemble LD A, B`() = test(0x78, "LD A,B")

    @Test
    fun `can disassemble LD A, C`() = test(0x79, "LD A,C")

    @Test
    fun `can disassemble LD A, D`() = test(0x7a, "LD A,D")

    @Test
    fun `can disassemble LD A, E`() = test(0x7b, "LD A,E")

    @Test
    fun `can disassemble LD A, H`() = test(0x7c, "LD A,H")

    @Test
    fun `can disassemble LD A, L`() = test(0x7d, "LD A,L")

    @Test
    fun `can disassemble LD A, (HL)`() = test(0x7e, "LD A,(HL)")

    @Test
    fun `can disassemble LD A, A`() = test(0x7f, "LD A,A")

    @Test
    fun `can disassemble ADD B`() = test(0x80, "ADD B")

    @Test
    fun `can disassemble ADD C`() = test(0x81, "ADD C")

    @Test
    fun `can disassemble ADD D`() = test(0x82, "ADD D")

    @Test
    fun `can disassemble ADD E`() = test(0x83, "ADD E")

    @Test
    fun `can disassemble ADD H`() = test(0x84, "ADD H")

    @Test
    fun `can disassemble ADD L`() = test(0x85, "ADD L")

    @Test
    fun `can disassemble ADD (HL)`() = test(0x86, "ADD (HL)")

    @Test
    fun `can disassemble ADD A`() = test(0x87, "ADD A")

    @Test
    fun `can disassemble ADC B`() = test(0x88, "ADC B")

    @Test
    fun `can disassemble ADC C`() = test(0x89, "ADC C")

    @Test
    fun `can disassemble ADC D`() = test(0x8a, "ADC D")

    @Test
    fun `can disassemble ADC E`() = test(0x8b, "ADC E")

    @Test
    fun `can disassemble ADC H`() = test(0x8c, "ADC H")

    @Test
    fun `can disassemble ADC L`() = test(0x8d, "ADC L")

    @Test
    fun `can disassemble ADC (HL)`() = test(0x8e, "ADC (HL)")

    @Test
    fun `can disassemble ADC A`() = test(0x8f, "ADC A")

    @Test
    fun `can disassemble SUB B`() = test(0x90, "SUB B")

    @Test
    fun `can disassemble SUB C`() = test(0x91, "SUB C")

    @Test
    fun `can disassemble SUB D`() = test(0x92, "SUB D")

    @Test
    fun `can disassemble SUB E`() = test(0x93, "SUB E")

    @Test
    fun `can disassemble SUB H`() = test(0x94, "SUB H")

    @Test
    fun `can disassemble SUB L`() = test(0x95, "SUB L")

    @Test
    fun `can disassemble SUB (HL)`() = test(0x96, "SUB (HL)")

    @Test
    fun `can disassemble SUB A`() = test(0x97, "SUB A")

    @Test
    fun `can disassemble SBC B`() = test(0x98, "SBC B")

    @Test
    fun `can disassemble SBC C`() = test(0x99, "SBC C")

    @Test
    fun `can disassemble SBC D`() = test(0x9a, "SBC D")

    @Test
    fun `can disassemble SBC E`() = test(0x9b, "SBC E")

    @Test
    fun `can disassemble SBC H`() = test(0x9c, "SBC H")

    @Test
    fun `can disassemble SBC L`() = test(0x9d, "SBC L")

    @Test
    fun `can disassemble SBC (HL)`() = test(0x9e, "SBC (HL)")

    @Test
    fun `can disassemble SBC A`() = test(0x9f, "SBC A")

    @Test
    fun `can disassemble AND B`() = test(0xa0, "AND B")

    @Test
    fun `can disassemble AND C`() = test(0xa1, "AND C")

    @Test
    fun `can disassemble AND D`() = test(0xa2, "AND D")

    @Test
    fun `can disassemble AND E`() = test(0xa3, "AND E")

    @Test
    fun `can disassemble AND H`() = test(0xa4, "AND H")

    @Test
    fun `can disassemble AND L`() = test(0xa5, "AND L")

    @Test
    fun `can disassemble AND (HL)`() = test(0xa6, "AND (HL)")

    @Test
    fun `can disassemble AND A`() = test(0xa7, "AND A")

    @Test
    fun `can disassemble XOR B`() = test(0xa8, "XOR B")

    @Test
    fun `can disassemble XOR C`() = test(0xa9, "XOR C")

    @Test
    fun `can disassemble XOR D`() = test(0xaa, "XOR D")

    @Test
    fun `can disassemble XOR E`() = test(0xab, "XOR E")

    @Test
    fun `can disassemble XOR H`() = test(0xac, "XOR H")

    @Test
    fun `can disassemble XOR L`() = test(0xad, "XOR L")

    @Test
    fun `can disassemble XOR (HL)`() = test(0xae, "XOR (HL)")

    @Test
    fun `can disassemble XOR A`() = test(0xaf, "XOR A")

    @Test
    fun `can disassemble OR B`() = test(0xb0, "OR B")

    @Test
    fun `can disassemble OR C`() = test(0xb1, "OR C")

    @Test
    fun `can disassemble OR D`() = test(0xb2, "OR D")

    @Test
    fun `can disassemble OR E`() = test(0xb3, "OR E")

    @Test
    fun `can disassemble OR H`() = test(0xb4, "OR H")

    @Test
    fun `can disassemble OR L`() = test(0xb5, "OR L")

    @Test
    fun `can disassemble OR (HL)`() = test(0xb6, "OR (HL)")

    @Test
    fun `can disassemble OR A`() = test(0xb7, "OR A")

    @Test
    fun `can disassemble CP B`() = test(0xb8, "CP B")

    @Test
    fun `can disassemble CP C`() = test(0xb9, "CP C")

    @Test
    fun `can disassemble CP D`() = test(0xba, "CP D")

    @Test
    fun `can disassemble CP E`() = test(0xbb, "CP E")

    @Test
    fun `can disassemble CP H`() = test(0xbc, "CP H")

    @Test
    fun `can disassemble CP L`() = test(0xbd, "CP L")

    @Test
    fun `can disassemble CP (HL)`() = test(0xbe, "CP (HL)")

    @Test
    fun `can disassemble CP A`() = test(0xbf, "CP A")

    @Test
    fun `can disassemble RET NZ`() = test(0xc0, "RET NZ")

    @Test
    fun `can disassemble POP BC`() = test(0xc1, "POP BC")

    @Test
    fun `can disassemble JP NZ, nn`() = test(0xc2, "JP NZ,0x1234", 0x34, 0x12)

    @Test
    fun `can disassemble JP nn`() = test(0xc3, "JP 0x1234", 0x34, 0x12)

    @Test
    fun `can disassemble CALL NZ, nn`() = test(0xc4, "CALL NZ,0x1234", 0x34, 0x12)

    @Test
    fun `can disassemble PUSH BC`() = test(0xc5, "PUSH BC")

    @Test
    fun `can disassemble ADD n`() = test(0xc6, "ADD 0x55", 0x55)

    @Test
    fun `can disassemble RST 0x00`() = test(0xc7, "RST 0x0000")

    @Test
    fun `can disassemble RET Z`() = test(0xc8, "RET Z")

    @Test
    fun `can disassemble RET`() = test(0xc9, "RET")

    @Test
    fun `can disassemble JP Z, nn`() = test(0xca, "JP Z,0x1234", 0x34, 0x12)

//    fun `can disassemble 0xcb`() = test(0xcb, "")

    @Test
    fun `can disassemble CALL Z, nn`() = test(0xcc, "CALL Z,0x1234", 0x34, 0x12)

    @Test
    fun `can disassemble CALL nn`() = test(0xcd, "CALL 0x1234", 0x34, 0x12)

    @Test
    fun `can disassemble ADC n`() = test(0xce, "ADC 0x55", 0x55)

    @Test
    fun `can disassemble RST 0x08`() = test(0xcf, "RST 0x0008")

    @Test
    fun `can disassemble RET NC`() = test(0xd0, "RET NC")

    @Test
    fun `can disassemble POP DE`() = test(0xd1, "POP DE")

    @Test
    fun `can disassemble JP NC, nn`() = test(0xd2, "JP NC,0x1234", 0x34, 0x12)

    @Test
    fun `can disassemble 0xd3`() = test(0xd3, "?? D3h")

    @Test
    fun `can disassemble CALL NC, nn`() = test(0xd4, "CALL NC,0x1234", 0x34, 0x12)

    @Test
    fun `can disassemble PUSH DE`() = test(0xd5, "PUSH DE")

    @Test
    fun `can disassemble SUB n`() = test(0xd6, "SUB 0x55", 0x55)

    @Test
    fun `can disassemble RST 0x10`() = test(0xd7, "RST 0x0010")

    @Test
    fun `can disassemble RET C`() = test(0xd8, "RET C")

    @Test
    fun `can disassemble RETI`() = test(0xd9, "RETI")

    @Test
    fun `can disassemble JP C, nn`() = test(0xda, "JP C,0x1234", 0x34, 0x12)

    @Test
    fun `can disassemble 0xdb`() = test(0xdb, "?? DBh")

    @Test
    fun `can disassemble CALL C, nn`() = test(0xdc, "CALL C,0x1234", 0x34, 0x12)

    @Test
    fun `can disassemble 0xdd`() = test(0xdd, "?? DDh")

    @Test
    fun `can disassemble SBC n`() = test(0xde, "SBC 0x55", 0x55)

    @Test
    fun `can disassemble RST 0x18`() = test(0xdf, "RST 0x0018")

    @Test
    fun `can disassemble LDH (n), A`() = test(0xe0, "LDH (0x55),A", 0x55)

    @Test
    fun `can disassemble POP HL`() = test(0xe1, "POP HL")

    @Test
    fun `can disassemble LDH (C), A`() = test(0xe2, "LDH (C),A")

    @Test
    fun `can disassemble 0xe3`() = test(0xe3, "?? E3h")

    @Test
    fun `can disassemble 0xe4`() = test(0xe4, "?? E4h")

    @Test
    fun `can disassemble PUSH HL`() = test(0xe5, "PUSH HL")

    @Test
    fun `can disassemble AND n`() = test(0xe6, "AND 0x55", 0x55)

    @Test
    fun `can disassemble RST 0x20`() = test(0xe7, "RST 0x0020")

    @Test
    fun `can disassemble ADD SP, e (positive operand)`() = test(0xe8, "ADD SP,0x55", 0x55)

    @Test
    fun `can disassemble ADD SP, e (negative operand)`() = test(0xe8, "ADD SP,-0x2b", 0xd5)

    @Test
    fun `can disassemble JP HL`() = test(0xe9, "JP HL")

    @Test
    fun `can disassemble LD (nn), A`() = test(0xea, "LD (0x1234),A", 0x34, 0x12)

    @Test
    fun `can disassemble 0xeb`() = test(0xeb, "?? EBh")

    @Test
    fun `can disassemble 0xec`() = test(0xec, "?? ECh")

    @Test
    fun `can disassemble 0xed`() = test(0xed, "?? EDh")

    @Test
    fun `can disassemble XOR n`() = test(0xee, "XOR 0x55", 0x55)

    @Test
    fun `can disassemble RST 0x28`() = test(0xef, "RST 0x0028") {
        val helper = EmulatorHelper(it.program)
        helper.writeRegister("SP", 0xffff)
        helper.step(TaskMonitor.DUMMY)
        println(helper.readRegister("SP"))
        println(helper.readRegister("PC"))
    }

    @Test
    fun `can disassemble LDH A, (n)`() = test(0xf0, "LDH A,(0x55)", 0x55)

    @Test
    fun `can disassemble POP AF`() = test(0xf1, "POP AF")

    @Test
    fun `can disassemble LDH A, (C)`() = test(0xf2, "LDH A,(C)")

    @Test
    fun `can disassemble DI`() = test(0xf3, "DI")

    @Test
    fun `can disassemble 0xf4`() = test(0xf4, "?? F4h")

    @Test
    fun `can disassemble PUSH AF`() = test(0xf5, "PUSH AF")

    @Test
    fun `can disassemble OR n`() = test(0xf6, "OR 0x55", 0x55)

    @Test
    fun `can disassemble RST 0x30`() = test(0xf7, "RST 0x0030")

    @Test
    fun `can disassemble LD HL, SP+e (positive operand)`() = test(0xf8, "LD HL,SP+0x55", 0x55)

    @Test
    fun `can disassemble LD HL, SP+e (negative operand)`() = test(0xf8, "LD HL,SP-0x2b", 0xd5)

    @Test
    fun `can disassemble LD SP, HL`() = test(0xf9, "LD SP,HL")

    @Test
    fun `can disassemble LD A, (nn)`() = test(0xfa, "LD A,(0x1234)", 0x34, 0x12)

    @Test
    fun `can disassemble EI`() = test(0xfb, "EI")

    @Test
    fun `can disassemble 0xfc`() = test(0xfc, "?? FCh")

    @Test
    fun `can disassemble 0xfd`() = test(0xfd, "?? FDh")

    @Test
    fun `can disassemble CP n`() = test(0xfe, "CP 0x55", 0x55)

    @Test
    fun `can disassemble RST 0x38`() = test(0xff, "RST 0x0038")

    private fun test(opcode: Int, expected: String, vararg args: Int, assertions: (codeUnit: CodeUnit) -> Unit = {}) {
        val codeUnit = disassemble(byteArrayOf(opcode.toByte(), *(args.map { it.toByte() }).toByteArray()))
        assertEquals(expected, codeUnit.toString())
        assertions(codeUnit)
    }

    private fun disassemble(bytes: ByteArray): CodeUnit {
        val consumer = object {}
        val program = ProgramDB("test", language, language.defaultCompilerSpec, consumer)

        val block = program.withTransaction { program.memory.loadBytes("rom", address(0x0000), bytes) }

        val disassembler = Disassembler.getDisassembler(program, TaskMonitor.DUMMY, null)
        return program.withTransaction {
            disassembler.disassemble(block.start, program.memory.loadedAndInitializedAddressSet)
            program.codeManager.getCodeUnitAt(block.start)
        }
    }
}
