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

import ghidra.program.model.listing.Program

inline fun <T> Program.withTransaction(
    description: String = "",
    crossinline f: () -> T,
): T {
    var success = false
    val id = startTransaction(description)
    try {
        val result = f()
        success = true
        return result
    } finally {
        endTransaction(id, success)
    }
}
