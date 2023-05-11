package fi.gekkio.ghidraboy.decompiler

import fi.gekkio.ghidraboy.DataTypes.u16
import fi.gekkio.ghidraboy.DataTypes.u8
import fi.gekkio.ghidraboy.GameBoyKind
import fi.gekkio.ghidraboy.GameBoyUtils
import fi.gekkio.ghidraboy.IntegrationTest
import fi.gekkio.ghidraboy.withTransaction
import ghidra.app.decompiler.DecompInterface
import ghidra.app.plugin.assembler.Assemblers
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramDB
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.DataType
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Parameter
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.ReturnParameterImpl
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class DecompilerTest : IntegrationTest() {
    private lateinit var program: Program
    private lateinit var decompiler: DecompInterface

    @Test
    fun `simple decompilation works`() {
        val f = assembleFunction(
            address(0x0000),
            """
            LD A, 0x55
            INC A
            LD (0x1234), A
            RET
            """.trimIndent()
        )
        assertDecompiled(
            f,
            """
            void FUN_0000(void)
            {
                DAT_1234 = 0x56;
                return;
            }
            """.trimIndent()
        )
    }

    @Test
    fun `Github issue 10`() {
        val f = assembleFunction(
            address(0x0000),
            """
            LD A, (0x1234)
            AND A
            JR NZ, 0x0009
            LD C, 0x6A
            LDH (C), A
            RETI
            """.trimIndent()
        )
        assertDecompiled(
            f,
            """
            void FUN_0000(void)
            {
                if (DAT_1234 == '\0') {
                    OCPS = 0;
                }
                IME(1);
                return;
            }
            """.trimIndent()
        )
    }

    @Test
    fun memcpy() {
        val f = assembleFunction(
            address(0x0000),
            """
  LD A, B
  OR C
  RET Z
  LD A, (DE)
  LD (HL+), A
  INC DE
  DEC BC
  JR 0x0000
            """.trimIndent(),
            name = "memcpy",
            params = listOf(
                parameter("dst", pointer(u8), register("HL")),
                parameter("src", pointer(u8), register("DE")),
                parameter("len", u16, register("BC"))
            )
        )
        assertDecompiled(
            f,
            """
            void memcpy(byte *dst,byte *src,word len)
            {
                for (; (byte)((byte)(len >> 8) | (byte)len) != 0; len = len - 1) {
                    *dst = *src;
                    src = src + 1;
                    dst = dst + 1;
                }
                return;
            }
            """.trimIndent()
        )
    }

    @Test
    fun memset() {
        val f = assembleFunction(
            address(0x0000),
            """
  LD D, A
  LD A, B
  OR C
  RET Z
  LD A, D
  LD (HL+), A
  DEC BC
  JR 0x0001
            """.trimIndent(),
            name = "memset",
            params = listOf(
                parameter("dst", pointer(u8), register("HL")),
                parameter("val", u8, register("A")),
                parameter("len", u16, register("BC"))
            )
        )
        assertDecompiled(
            f,
            """
            void memset(byte *dst,byte val,word len)
            {
                for (; (byte)((byte)(len >> 8) | (byte)len) != 0; len = len - 1) {
                    *dst = val;
                    dst = dst + 1;
                }
                return;
            }
            """.trimIndent()
        )
    }

    @Test
    fun `upper nibble popcount`() {
        val f = assembleFunction(
            address(0x0000),
            """
  LD D, A
  XOR A
  LD E, A
  SLA D
  ADC E
  SLA D
  ADC E
  SLA D
  ADC E
  SLA D
  ADC E
  RET
            """.trimIndent(),
            name = "popcnt4_upper",
            params = listOf(
                parameter("value", u8, register("A"))
            ),
            returnParam = returnParameter(u8, register("A"))
        )
        assertDecompiled(
            f,
            """
            byte popcnt4_upper(byte value)
            {
                return ((-((char)(value << 1) >> 7) - ((char)value >> 7)) - ((char)(value << 2) >> 7)) -
                    ((char)(value << 3) >> 7); 
            }
            """.trimIndent()
        )
    }

    @Test
    fun `read_joypad_state`() {
        val f = assembleFunction(
            address(0x0000),
            """
  LD A, 0x20
  LDH (0x00), A
  LDH A, (0x00)
  LDH A, (0x00)
  CPL
  AND 0x0F
  SWAP A
  LD B, A
  LD A, 0x10
  LDH (0x00), A
  LDH A, (0x00)
  LDH A, (0x00)
  LDH A, (0x00)
  LDH A, (0x00)
  LDH A, (0x00)
  LDH A, (0x00)
  CPL
  AND 0x0F
  OR B
  LD B, A
  LD A, 0x30
  LDH (0x00), A
  LD A, B
  RET
            """.trimIndent(),
            name = "read_joypad_state",
            returnParam = returnParameter(u8, register("A"))
        )
        assertDecompiled(
            f,
            """
            byte read_joypad_state(void)
            {
                byte bVar1;
                byte bVar2;
                P1 = 0x20;
                bVar1 = P1;
                P1 = 0x10;
                bVar2 = P1;
                P1 = 0x30;
                return ~bVar2 & 0xf | ~bVar1 << 4;
            }
            """.trimIndent()
        )
    }

    @Test
    fun `sla8_to_16`() {
        val f = assembleFunction(
            address(0x0000),
            """
  LD C, A
  XOR A
  SLA C
  RLA
  SLA C
  RLA
  SLA C
  RLA
  SLA C
  RLA
  LD B, A
  RET
            """.trimIndent(),
            name = "sla8_to_16",
            params = listOf(
                parameter("value", u8, register("A"))
            ),
            returnParam = returnParameter(u16, register("BC"))
        )
        assertDecompiled(
            f,
            """
            word sla8_to_16(byte value)
            {
                return CONCAT11((((value >> 7) << 1 | (byte)(value << 1) >> 7) << 1 | (byte)(value << 2) >> 7) <<
                    1 | (byte)(value << 3) >> 7,value << 4);
            }
            """.trimIndent()
        )
    }

    @Test
    fun `DAA decompilation`() {
        val f = assembleFunction(
            address(0x0000),
            """
  LD A, 0x01
  ADD C
  DAA
  LD C, A
  RET Z
  INC C
  RET
            """.trimIndent(),
            name = "daa",
            params = listOf(
                parameter("value", u8, register("C"))
            ),
            returnParam = returnParameter(u8, register("C"))
        )
        assertDecompiled(
            f,
            """
            byte daa(byte value)
            {
                char cVar1;
                byte bVar2;
                cVar1 = daaOperand(value + 1,0xfe < value,((value & 0xf) + 1 & 0x10) != 0,0);
                bVar2 = value + 1 + cVar1;
                if (bVar2 == 0) {
                    return bVar2;
                }
                return bVar2 + 1;
            }
            """.trimIndent()
        )
    }

    @BeforeAll
    override fun beforeAll() {
        super.beforeAll()
        decompiler = DecompInterface()
    }

    @BeforeEach
    fun beforeEach() {
        val consumer = object {}
        program = ProgramDB("test", language, language.defaultCompilerSpec, consumer)
        program.withTransaction {
            program.memory.createInitializedBlock("rom", address(0x0000), 0x8000, 0, TaskMonitor.DUMMY, false)
            GameBoyUtils.addHardwareBlocks(program, GameBoyKind.CGB, MessageLog())
            GameBoyUtils.populateHardwareBlocks(program, GameBoyKind.CGB)
        }
        assertTrue(decompiler.openProgram(program)) { "Failed to initialize decompiler" }
    }

    @AfterEach
    fun afterEach() {
        decompiler.closeProgram()
    }

    @AfterAll
    fun afterAll() {
        decompiler.dispose()
    }

    private fun assembleFunction(
        address: Address,
        code: String,
        name: String? = null,
        params: List<Parameter>? = null,
        returnParam: Parameter? = null
    ): Function = program.withTransaction {
        val instructions: Iterable<Instruction> = Assemblers.getAssembler(program).assemble(address, *code.lines().toTypedArray())
        val addressSet = AddressSet()
        for (instruction in instructions) {
            addressSet.add(instruction.minAddress, instruction.maxAddress)
        }
        program.functionManager.createFunction(name, address, addressSet, SourceType.USER_DEFINED).apply {
            setCustomVariableStorage(true)
            val callingConvention = "default"
            val force = true
            if (params != null) {
                updateFunction(
                    callingConvention,
                    returnParam,
                    params,
                    Function.FunctionUpdateType.CUSTOM_STORAGE,
                    force,
                    SourceType.USER_DEFINED
                )
            } else {
                updateFunction(
                    callingConvention,
                    returnParam,
                    Function.FunctionUpdateType.CUSTOM_STORAGE,
                    force,
                    SourceType.USER_DEFINED
                )
            }
        }
    }

    private fun decompile(function: Function) =
        decompiler.decompileFunction(function, 10, TaskMonitor.DUMMY).also {
            assertTrue(it.decompileCompleted()) { "Decompilation did not complete" }
        }.decompiledFunction.c

    private fun formatCode(code: String) = code.lineSequence()
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .joinToString(separator = "\n")
    private fun assertDecompiled(function: Function, @Language("C") code: String) =
        assertEquals(formatCode(code), formatCode(decompile(function)))

    private fun parameter(name: String, type: DataType, register: Register) =
        ParameterImpl(name, type, register, program)
    private fun returnParameter(type: DataType, register: Register) =
        ReturnParameterImpl(type, register, program)
    private fun pointer(type: DataType) = PointerDataType(type)
    private fun register(name: String) = program.getRegister(name)
}
