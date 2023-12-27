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
import ghidra.GhidraApplicationLayout
import ghidra.framework.Application
import ghidra.framework.GModule
import ghidra.framework.HeadlessGhidraApplicationConfiguration
import org.junit.jupiter.api.extension.Extension

class GhidraApplication : Extension {
    init {
        initialize()
    }

    companion object {
        private var initialized = false

        fun initialize() =
            synchronized(this) {
                if (initialized) return
                val layout =
                    object : GhidraApplicationLayout() {
                        override fun findGhidraModules(): MutableMap<String, GModule> =
                            mutableMapOf(
                                "GhidraBoy" to
                                    GModule(applicationRootDirs, ResourceFile("./")),
                            ).apply {
                                putAll(super.findGhidraModules())
                            }
                    }
                val configuration = HeadlessGhidraApplicationConfiguration()
                Application.initializeApplication(layout, configuration)
                initialized = true
            }
    }
}
