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

import generic.jar.ResourceFile
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider
import ghidra.program.model.address.Address
import ghidra.program.model.lang.Language
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.extension.ExtendWith
import java.io.File

@ExtendWith(GhidraApplication::class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
open class IntegrationTest {
    protected lateinit var language: Language

    @BeforeAll
    open fun beforeAll() {
        val defs = ResourceFile(File("data/languages/sm83.ldefs"))
        val provider = SleighLanguageProvider(defs)
        Assertions.assertFalse(provider.hadLoadFailure())
        val languageDescription = provider.languageDescriptions.single()

        Assertions.assertEquals("Sharp SM83", languageDescription.description)
        Assertions.assertEquals("SM83", languageDescription.processor.toString())

        language = provider.getLanguage(languageDescription.languageID)
    }

    protected fun address(offset: Long): Address = language.addressFactory.defaultAddressSpace.getAddress(offset)
}
