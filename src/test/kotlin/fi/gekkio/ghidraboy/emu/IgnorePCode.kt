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

import ghidra.pcode.emulate.BreakCallBack
import ghidra.pcode.pcoderaw.PcodeOpRaw

class IgnorePCode : BreakCallBack() {
    var triggered: Boolean = false
        private set

    override fun pcodeCallback(op: PcodeOpRaw): Boolean {
        triggered = true
        return true
    }
}
