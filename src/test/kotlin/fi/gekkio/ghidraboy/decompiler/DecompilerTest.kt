package fi.gekkio.ghidraboy.decompiler

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
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
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

    private fun assembleFunction(address: Address, code: String): ghidra.program.model.listing.Function = program.withTransaction {
        val instructions: Iterable<Instruction> = Assemblers.getAssembler(program).assemble(address, *code.lines().toTypedArray())
        val addressSet = AddressSet()
        for (instruction in instructions) {
            addressSet.add(instruction.minAddress, instruction.maxAddress)
        }
        program.functionManager.createFunction(null, address, addressSet, SourceType.DEFAULT)
    }

    private fun decompile(function: ghidra.program.model.listing.Function) =
        decompiler.decompileFunction(function, 10, TaskMonitor.DUMMY).also {
            assertTrue(it.decompileCompleted()) { "Decompilation did not complete" }
        }.decompiledFunction.c

    private fun formatCode(code: String) = code.lineSequence()
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .joinToString(separator = "\n")
    private fun assertDecompiled(function: ghidra.program.model.listing.Function, @Language("C") code: String) =
        assertEquals(formatCode(code), formatCode(decompile(function)))
}
